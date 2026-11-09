# Intégration Frontend Lovable — PhishGuard CI

**Version :** 1.0  
**Date :** 7 novembre 2026  
**Backend :** PhishGuard CI API v0.1.0  
**Frontend cible :** Lovable (React/Vite/TypeScript recommandé)

---

## 1. Architecture d'intégration

```
┌─────────────────┐     HTTPS      ┌──────────────────┐
│   Lovable       │ ◄─────────────► │  FastAPI Backend │
│   Frontend      │   /api/v1/*     │  PhishGuard CI   │
└─────────────────┘                 └──────────────────┘
```

**Principes :**
- Backend = source de vérité (scoring, classification, persistance)
- Frontend = affichage, interaction utilisateur, gestion d'état
- Aucune logique de scoring côté frontend
- TemplateExplainer = seule source d'explication (Hermes désactivé)

---

## 2. Configuration requise

### 2.1 Variables d'environnement frontend

```env
# .env.local (Lovable)
VITE_API_BASE_URL=https://api.phishguard-ci.example.com/api/v1
VITE_APP_NAME=PhishGuard CI
VITE_DEFAULT_CONTENT_TYPE=MESSAGE
```

### 2.2 CORS backend (déjà configuré)

```python
# app/config.py
cors_origins: list[str] = [
    "http://localhost:3000",      # CRA
    "http://localhost:5173",      # Vite
    "https://votre-app.lovable.app"  # À ajouter pour production
]
```

**Action :** Ajouter l'URL Lovable de production dans `PHISHGUARD_CORS_ORIGINS` via variable d'env.

---

## 3. Client API recommandé

### 3.1 Configuration Axios/Fetch

```typescript
// lib/api.ts
const API_BASE = import.meta.env.VITE_API_BASE_URL;

const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true, // Indispensable pour cookies HttpOnly
  headers: {
    'Content-Type': 'application/json',
  },
});

// Intercepteur pour CSRF token
api.interceptors.request.use((config) => {
  const csrfToken = document.cookie
    .split('; ')
    .find(row => row.startsWith('csrf_token='))
    ?.split('=')[1];
  
  if (csrfToken && ['post', 'patch', 'delete'].includes(config.method || '')) {
    config.headers['X-CSRF-Token'] = csrfToken;
  }
  
  return config;
});

// Gestion 401 → refresh token
api.interceptors.response.use(
  response => response,
  async error => {
    if (error.response?.status === 401 && !error.config._retry) {
      error.config._retry = true;
      try {
        await api.post('/auth/refresh');
        return api.request(error.config);
      } catch {
        // Refresh échoué → déconnexion
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export default api;
```

---

## 4. Flux d'authentification

### 4.1 Inscription

```typescript
// hooks/useAuth.ts
async function register(email: string, password: string) {
  const response = await api.post('/auth/register', { email, password });
  // Pas de cookies définis à l'inscription
  // Rediriger vers /login
}
```

### 4.2 Connexion

```typescript
async function login(email: string, password: string, mfaCode?: string) {
  const response = await api.post('/auth/login', { 
    email, 
    password, 
    mfa_code: mfaCode 
  });
  
  // Cookies définis automatiquement par le backend :
  // - session (HttpOnly)
  // - csrf_token (lisible en JS)
  // - refresh_token (HttpOnly)
  
  // Tokens dans la réponse :
  const { access_token, refresh_token, user } = response.data;
  
  // Stocker access_token en mémoire (pas localStorage !)
  setAccessToken(access_token);
  setUser(user);
  
  return user;
}
```

### 4.3 Configuration MFA (Admin uniquement)

```typescript
// hooks/useMFA.ts
interface MFASetupResponse {
  secret: string;           // Secret chiffré (Fernet) - pour stockage si besoin
  provisioning_uri: string; // URI otpauth:// pour QR code
}

interface MFAVerifyResponse {
  mfa_enabled: boolean;
  message: string;
}

async function setupMFA(): Promise<MFASetupResponse> {
  const response = await api.post('/auth/mfa/setup', {});
  return response.data;
}

async function verifyMFA(code: string): Promise<MFAVerifyResponse> {
  const response = await api.post('/auth/mfa/verify', { code });
  return response.data;
}

async function disableMFA(code: string): Promise<MFAVerifyResponse> {
  const response = await api.post('/auth/mfa/disable', { code });
  return response.data;
}
```

**Flux MFA complet côté frontend :**

```typescript
// components/MFASetup.tsx
export function MFASetup() {
  const [qrUri, setQrUri] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [step, setStep] = useState<'setup' | 'verify'>('setup');
  const [error, setError] = useState<string | null>(null);
  const [lockedUntil, setLockedUntil] = useState<Date | null>(null);

  const handleSetup = async () => {
    try {
      setError(null);
      const { provisioning_uri } = await setupMFA();
      setQrUri(provisioning_uri);
      setStep('verify');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Erreur setup MFA');
    }
  };

  const handleVerify = async () => {
    try {
      setError(null);
      const result = await verifyMFA(code);
      if (result.mfa_enabled) {
        // MFA activé avec succès
        onMFAEnabled();
      }
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      if (err.response?.status === 429) {
        // Compte verrouillé - extraire retry-after
        const retryAfter = err.response.headers['retry-after'];
        setLockedUntil(new Date(Date.now() + (retryAfter ? retryAfter * 1000 : 15 * 60 * 1000)));
      }
      setError(detail || 'Code invalide');
    }
  };

  if (step === 'setup') {
    return (
      <button onClick={handleSetup} disabled={lockedUntil && lockedUntil > new Date()}>
        Initialiser MFA
      </button>
    );
  }

  return (
    <div>
      {qrUri && (
        <div>
          <p>Scannez ce QR code avec votre application TOTP (Google Authenticator, Authy, etc.)</p>
          <img src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrUri)}`} alt="MFA QR Code" />
          <p>Secret chiffré (backup) : {qrUri.split('secret=')[1]?.split('&')[0]}</p>
        </div>
      )}
      <input 
        type="text" 
        value={code} 
        onChange={e => setCode(e.target.value)} 
        placeholder="Code à 6 chiffres"
        maxLength={6}
        disabled={lockedUntil && lockedUntil > new Date()}
      />
      {lockedUntil && lockedUntil > new Date() && (
        <p className="text-red-500">Compte verrouillé. Réessayez dans {Math.ceil((lockedUntil.getTime() - Date.now()) / 60000)} min.</p>
      )}
      {error && <p className="text-red-500">{error}</p>}
      <button onClick={handleVerify} disabled={!code || (lockedUntil && lockedUntil > new Date())}>
        Vérifier et activer MFA
      </button>
    </div>
  );
}
```

### 4.4 Déconnexion

```typescript
async function logout() {
  await api.post('/auth/logout');
  clearAccessToken();
  clearUser();
  // Cookies nettoyés par le backend
  router.push('/login');
}
```

### 4.4 Renouvellement silencieux

```typescript
// Intercepteur axios gère automatiquement le 401
// Mais on peut aussi déclencher manuellement :
async function refreshAccessToken() {
  const response = await api.post('/auth/refresh');
  setAccessToken(response.data.access_token);
  return response.data.access_token;
}
```

### 4.5 Protection des routes

```typescript
// components/ProtectedRoute.tsx
export function ProtectedRoute({ children, requiredRole }: { 
  children: React.ReactNode; 
  requiredRole?: 'USER' | 'ADMIN' | 'SUPER_ADMIN' 
}) {
  const { user, loading } = useAuth();
  
  if (loading) return <Spinner />;
  if (!user) return <Navigate to="/login" replace />;
  if (requiredRole && !hasRole(user.role, requiredRole)) {
    return <Navigate to="/dashboard" replace />;
  }
  
  return <>{children}</>;
}
```

---

## 5. Flux d'analyse complet

### 5.1 Soumission

```typescript
// hooks/useAnalysis.ts
async function submitAnalysis(content: string, contentType: ContentType = 'MESSAGE') {
  setLoading(true);
  setError(null);
  
  try {
    const response = await api.post('/analyses', { 
      content, 
      content_type: contentType 
    });
    
    // Mettre à jour le cache local
    queryClient.invalidateQueries({ queryKey: ['analyses'] });
    queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
    
    return response.data;
  } catch (err: any) {
    if (err.response?.status === 429) {
      const retryAfter = err.response.headers['retry-after'];
      setError(`Quota dépassé. Réessayez dans ${retryAfter} secondes.`);
    } else if (err.response?.status === 422) {
      setError('Contenu trop long (max 1000 caractères)');
    } else {
      setError('Erreur lors de l\'analyse');
    }
    throw err;
  } finally {
    setLoading(false);
  }
}
```

### 5.2 Affichage du résultat

```typescript
// components/AnalysisResult.tsx
interface AnalysisResultProps {
  data: AnalysisResponse;
}

export function AnalysisResult({ data }: AnalysisResultProps) {
  const severityClass = {
    CLEAN: 'text-green-600 bg-green-50',
    SUSPICIOUS: 'text-yellow-600 bg-yellow-50',
    CRITICAL: 'text-red-600 bg-red-50',
  }[data.classification];

  return (
    <div className="space-y-4">
      {/* Score et classification */}
      <div className={`p-4 rounded-lg ${severityClass}`}>
        <div className="flex justify-between items-center">
          <span className="text-2xl font-bold">Score: {data.score}/100</span>
          <span className="text-lg font-semibold">
            {data.classification}
          </span>
        </div>
        <div className="text-sm mt-1">
          Fiabilité: {data.reliability_level} • 
          Évaluation: {data.assessment_status} •
          Source: {data.explanation_source} (v{data.template_version})
        </div>
      </div>

      {/* Explication */}
      <div className="prose prose-sm max-w-none">
        {data.explanation}
      </div>

      {/* Indicateurs détaillés */}
      <details className="group">
        <summary className="cursor-pointer font-medium">
          Voir les {data.indicators.length} indicateurs détectés
        </summary>
        <ul className="mt-2 space-y-2">
          {data.indicators.map((ind, i) => (
            <li key={i} className="flex items-start gap-2 text-sm">
              <span className="font-mono text-xs bg-gray-100 px-1 rounded">
                {ind.code}
              </span>
              <span className="font-medium">{ind.label}</span>
              <span className="text-gray-500">
                (+{ind.points_awarded} pts)
              </span>
              {ind.evidence_snippet && (
                <span className="text-gray-400 italic">
                  « {ind.evidence_snippet} »
                </span>
              )}
              <span className={`px-1.5 py-0.5 text-xs rounded ${
                ind.validation_status === 'VALIDEE' 
                  ? 'bg-green-100 text-green-700' 
                  : 'bg-yellow-100 text-yellow-700'
              }`}>
                {ind.validation_status}
              </span>
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}
```

### 5.3 Gestion des états

```typescript
// États à gérer côté frontend
interface AnalysisState {
  // Soumission
  isSubmitting: boolean;
  submitError: string | null;
  
  // Résultat
  currentAnalysis: AnalysisResponse | null;
  
  // Historique
  analyses: AnalysisResponse[];
  analysesLoading: boolean;
  
  // Quota
  quota: QuotaStatus | null;
}
```

---

## 6. Historique et tableau de bord

### 6.1 Liste paginée

```typescript
// hooks/useAnalyses.ts
function useAnalyses(page = 1, limit = 20) {
  return useQuery({
    queryKey: ['analyses', page, limit],
    queryFn: () => api.get('/analyses', { params: { limit, offset: (page - 1) * limit } }),
    staleTime: 30_000,
  });
}
```

### 6.2 Statistiques utilisateur

```typescript
function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => api.get('/dashboard/user/stats'),
    staleTime: 60_000,
  });
}
```

### 6.3 Quota temps réel

```typescript
function useQuota() {
  return useQuery({
    queryKey: ['quota'],
    queryFn: () => api.get('/auth/me/quota'),
    refetchInterval: 30_000, // Rafraîchir toutes les 30s
  });
}
```

---

## 7. Interface administrateur

### 7.1 Vérification rôle

```typescript
// hooks/useAdmin.ts
function useAdmin() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN';
  const isSuperAdmin = user?.role === 'SUPER_ADMIN';
  
  return { isAdmin, isSuperAdmin };
}
```

### 7.2 Gestion utilisateurs

```typescript
// AdminUsersPage.tsx
export function AdminUsersPage() {
  const { isAdmin } = useAdmin();
  if (!isAdmin) return <Navigate to="/dashboard" replace />;
  
  const { data } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => api.get('/dashboard/admin/users'),
  });
  
  const updateUser = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<User> }) => 
      api.patch(`/dashboard/admin/users/${id}`, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin-users'] }),
  });
  
  return (
    <table>
      <thead>
        <tr>
          <th>Email</th>
          <th>Rôle</th>
          <th>Actif</th>
          <th>Analyses</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {data?.map(user => (
          <tr key={user.id}>
            <td>{user.email}</td>
            <td>
              <select 
                value={user.role} 
                onChange={e => updateUser.mutate({ id: user.id, data: { role: e.target.value } })}
                disabled={!isSuperAdmin}
              >
                <option value="USER">Utilisateur</option>
                <option value="ADMIN">Admin</option>
                <option value="SUPER_ADMIN">Super Admin</option>
              </select>
            </td>
            <td>
              <input 
                type="checkbox" 
                checked={user.is_active} 
                onChange={e => updateUser.mutate({ id: user.id, data: { is_active: e.target.checked } })}
              />
            </td>
            <td>{user.analyses_count}</td>
            <td>
              <button onClick={() => navigate(`/admin/users/${user.id}`)}>
                Détail
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
```

---

## 8. Gestion d'erreurs et UX

### 8.1 Composant d'erreur global

```typescript
// components/ErrorBoundary.tsx
export function ErrorDisplay({ error, onRetry }: { 
  error: ApiError | null; 
  onRetry?: () => void 
}) {
  if (!error) return null;
  
  const messages: Record<number, string> = {
    401: 'Session expirée. Redirection vers la connexion...',
    403: 'Accès refusé. Vous n\'avez pas les permissions nécessaires.',
    404: 'Ressource introuvable.',
    422: 'Données invalides. Vérifiez votre saisie.',
    429: `Trop de requêtes. Réessayez dans ${error.retryAfter || 'quelques'} secondes.`,
    500: 'Erreur serveur. Veuillez réessayer plus tard.',
  };
  
  return (
    <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
      <p className="text-red-700">{messages[error.status] || error.message}</p>
      {onRetry && (
        <button 
          onClick={onRetry} 
          className="mt-2 px-3 py-1 bg-red-600 text-white rounded"
        >
          Réessayer
        </button>
      )}
    </div>
  );
}
```

### 8.2 États de chargement

```typescript
// Composants de skeleton loading
export function AnalysisSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="h-8 bg-gray-200 rounded w-1/4"></div>
      <div className="h-4 bg-gray-200 rounded w-3/4"></div>
      <div className="h-4 bg-gray-200 rounded w-1/2"></div>
      <details>
        <summary className="cursor-pointer">Indicateurs...</summary>
        <ul className="space-y-2 mt-2">
          {[1,2,3].map(i => (
            <li key={i} className="h-4 bg-gray-200 rounded w-full"></li>
          ))}
        </ul>
      </details>
    </div>
  );
}
```

---

## 9. Exemples de requêtes/réponses

Voir `docs/EXEMPLES_API.md` pour des exemples complets JSON.

---

## 10. Checklist de déploiement frontend

| Élément | Status | Notes |
|---|---|---|
| URL API configurée | ⬜ | `VITE_API_BASE_URL` |
| CORS backend mis à jour | ⬜ | Ajouter domaine Lovable |
| Cookies `withCredentials: true` | ⬜ | Obligatoire |
| Intercepteur CSRF | ⬜ | Header `X-CSRF-Token` |
| Intercepteur 401 → refresh | ⬜ | Renouvellement silencieux |
| Stockage access_token mémoire | ⬜ | Pas de localStorage |
| Gestion 401/403/429 | ⬜ | UI appropriée |
| Protection routes admin | ⬜ | Vérification rôle |
| Tests d'intégration | ⬜ | Cypress/Playwright |

---

## 11. Points d'attention

1. **Hermes désactivé** : `explanation_source` toujours `"TEMPLATE"` ; ne pas construire d'UI spécifique Hermes
2. **Fournisseurs externes** : Désactivés ; indicateurs `PROPOSITION_NON_VALIDEE` = pondérations indicatives
3. **Seuils F1/F2** : Inactifs ; ne pas coder de logique métier dessus
4. **Données minimisées** : Pas d'URL complète, pas de domaine en clair dans l'historique
5. **Quota strict** : 30/jour ; afficher `remaining` et `reset_at` en temps réel

---

*Document généré pour l'intégration Lovable — PhishGuard CI Backend v0.1.0*