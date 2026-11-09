# Contrat API Frontend — PhishGuard CI

**Version :** 1.0  
**Date :** 7 novembre 2026  
**Base URL :** `/api/v1` (préfixe global)  
**Format :** JSON uniquement  
**Authentification :** JWT Bearer + Cookies HttpOnly (session + CSRF)

---

## 1. Authentification et sessions

### 1.1 Inscription
**POST** `/auth/register`

**Request :**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response 201 :**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "role": "USER",
  "is_active": true,
  "is_test_account": false,
  "created_at": "2026-11-07T10:30:00Z",
  "last_login_at": null
}
```

**Erreurs :**
- `409` : Email déjà enregistré
- `422` : Validation email/mot de passe

---

### 1.2 Connexion
**POST** `/auth/login`

**Request :**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "mfa_code": "123456"  // Requis seulement pour admins
}
```

**Response 200 :**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "role": "USER",
    "is_active": true,
    "is_test_account": false,
    "created_at": "2026-11-07T10:30:00Z",
    "last_login_at": "2026-11-07T10:30:00Z"
  }
}
```

**Cookies définis :**
- `session` : HttpOnly, Secure, SameSite=Lax, max-age=1800s
- `csrf_token` : Non HttpOnly (lecture JS), Secure, SameSite=Lax, max-age=1800s

**Erreurs :**
- `401` : Identifiants invalides
- `403` : Compte désactivé
- `401` + `detail: "MFA code required for admin accounts"` : Admin sans code MFA

---

### 1.3 Déconnexion
**POST** `/auth/logout`

**Cookies requis :** `session`

**Response 200 :**
```json
{ "message": "Logged out successfully" }
```

**Cookies supprimés :** `session`, `csrf_token`

---

### 1.4 Renouvellement access token
**POST** `/auth/refresh`

**Options pour le refresh token :**
1. Cookie `refresh_token`
2. Header `Authorization: Bearer <refresh_token>`

**Response 200 :**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer"
}
```

**Erreurs :**
- `401` : Refresh token manquant, invalide, expiré ou utilisateur inactif

---

### 1.5 Profil utilisateur courant
**GET** `/auth/me`

**Auth :** Bearer token ou cookie `session`

**Response 200 :**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "role": "USER",
  "is_active": true,
  "is_test_account": false,
  "created_at": "2026-11-07T10:30:00Z",
  "last_login_at": "2026-11-07T10:30:00Z"
}
```

---

### 1.6 Statut quota
**GET** `/auth/me/quota`

**Auth :** Bearer token ou cookie `session`

**Response 200 :**
```json
{
  "max_per_day": 30,
  "used_today": 5,
  "remaining": 25,
  "reset_at": "2026-11-07T23:59:59.999999Z"
}
```

---

### 1.7 Révocation de toutes les sessions
**DELETE** `/auth/me/sessions`

**Auth :** Bearer token ou cookie `session` + header `X-CSRF-Token` (depuis cookie `csrf_token`)

**Response 200 :**
```json
{ "message": "Revoked 3 sessions" }
```

**Cookies supprimés :** `session`, `csrf_token`

---

## 2. Analyse de contenu

### 2.1 Créer une analyse
**POST** `/analyses`

**Headers requis :**
- `Authorization: Bearer <access_token>` **OU** cookie `session`
- `X-CSRF-Token: <csrf_token>` (depuis cookie `csrf_token`)

**Request :**
```json
{
  "content": "Veuillez renseigner votre code PIN Orange Money sur http://phishing.top/login",
  "content_type": "MESSAGE"
}
```

**Contraintes :**
- `content` : 1-10000 caractères (configurable via `PHISHGUARD_MAX_INPUT_CHARS`)
- `content_type` : `SMS` | `MESSAGE` | `EMAIL` | `URL` (défaut: `MESSAGE`)

**Response 201 :**
```json
{
  "analysis_ref": "c4d2e1a9-7b3f-4e8a-9f12-3456789abcde",
  "status": "PARTIAL",
  "score": 85,
  "classification": "CRITICAL",
  "reliability_level": "MEDIUM",
  "assessment_status": "CONCLUSIVE",
  "indicators": [
    {
      "code": "REPUTATION_MALICIOUS_EXTERNAL",
      "category": "REPUTATION_URL_DOMAIN",
      "nature": "PROVIDER_SIGNAL",
      "label": "Lien signalé malveillant par un service de réputation",
      "points_awarded": 30,
      "evidence_snippet": null,
      "validation_status": "VALIDEE"
    },
    {
      "code": "OTP_PIN_REQUEST",
      "category": "SENSITIVE_DATA_REQUEST",
      "nature": "HEURISTIC_DETECTION",
      "label": "Formulation explicite de demande de code PIN",
      "points_awarded": 20,
      "evidence_snippet": "veuillez renseigner votre code secret PIN Orange Money",
      "validation_status": "VALIDEE"
    },
    {
      "code": "URGENCY_PRESSURE",
      "category": "URGENCY_MANIPULATION",
      "nature": "HEURISTIC_DETECTION",
      "label": "Menace de blocage sous délai court",
      "points_awarded": 15,
      "evidence_snippet": "compte sera bloqué sous 24h",
      "validation_status": "VALIDEE"
    },
    {
      "code": "PUBLIC_IP_LITERAL",
      "category": "URL_STRUCTURE_ANOMALIES",
      "nature": "STRUCTURAL_SIGNAL",
      "label": "Lien utilisant une adresse IP publique",
      "points_awarded": 15,
      "evidence_snippet": null,
      "validation_status": "PROPOSITION_NON_VALIDEE"
    },
    {
      "code": "SUSPICIOUS_TLD",
      "category": "URL_STRUCTURE_ANOMALIES",
      "nature": "STRUCTURAL_SIGNAL",
      "label": "Extension de domaine figurant sur la liste de surveillance statistique",
      "points_awarded": 5,
      "evidence_snippet": null,
      "validation_status": "PROPOSITION_NON_VALIDEE"
    },
    {
      "code": "BRAND_MENTION_INFORMATIVE",
      "category": "BRAND_IMPERSONATION_MISMATCH",
      "nature": "INFORMATIVE_SIGNAL",
      "label": "Mention textuelle d'une marque sans domaine officiel rattaché",
      "points_awarded": 0,
      "evidence_snippet": null,
      "validation_status": "VALIDEE"
    }
  ],
  "explanation": "Ce message présente un niveau de risque CRITICAL (score simulé de 85/100). L'exécution du pipeline est PARTIAL, la couverture des vérifications est MOYENNE, et l'évaluation est jugée CONCLUSIVE sur les signaux observés.",
  "explanation_source": "TEMPLATE",
  "template_version": "1.0.0",
  "scoring_version": "1.2.0"
}
```

**Erreurs :**
- `422` : Contenu trop long (> 10000 chars)
- `429` : Quota journalier dépassé (header `Retry-After` en secondes)
- `401` : Non authentifié

---

### 2.2 Lister les analyses
**GET** `/analyses?limit=50&offset=0`

**Auth :** Bearer token ou cookie `session`

**Paramètres :**
- `limit` : 1-100 (défaut 50)
- `offset` : ≥0 (défaut 0)

**Response 200 :**
```json
[
  {
    "analysis_ref": "uuid",
    "status": "COMPLETED",
    "score": 85,
    "classification": "CRITICAL",
    "reliability_level": "MEDIUM",
    "assessment_status": "CONCLUSIVE",
    "indicators": [...],
    "explanation": "Ce message présente un niveau de risque...",
    "explanation_source": "TEMPLATE",
    "template_version": "1.0.0",
    "scoring_version": "1.2.0"
  }
]
```

---

### 2.3 Obtenir une analyse
**GET** `/analyses/{analysis_ref}`

**Auth :** Bearer token ou cookie `session`

**Response 200 :** (même structure que création)

**Note :** L'explication est régénérée avec la version actuelle du template (D20)

**Erreurs :**
- `404` : Analyse introuvable ou n'appartient pas à l'utilisateur

---

### 2.4 Supprimer une analyse
**DELETE** `/analyses/{analysis_ref}`

**Auth :** Bearer token ou cookie `session` + `X-CSRF-Token`

**Response 204** (vide)

**Erreurs :**
- `404` : Analyse introuvable ou n'appartient pas à l'utilisateur

---

## 3. Tableau de bord utilisateur

### 3.1 Statistiques
**GET** `/dashboard/user/stats`

**Auth :** Bearer token ou cookie `session`

**Response 200 :**
```json
{
  "total_analyses": 42,
  "by_classification": { "CLEAN": 15, "SUSPICIOUS": 12, "CRITICAL": 15 },
  "by_content_type": { "MESSAGE": 20, "SMS": 10, "EMAIL": 8, "URL": 4 },
  "recent_7_days": 8
}
```

---

### 3.2 Analyses récentes
**GET** `/dashboard/user/recent?limit=10`

**Auth :** Bearer token ou cookie `session`

**Paramètres :**
- `limit` : 1-100 (défaut 10)

**Response 200 :**
```json
[
  {
    "analysis_ref": "uuid",
    "content_type": "MESSAGE",
    "status": "COMPLETED",
    "score": 85,
    "classification": "CRITICAL",
    "reliability_level": "MEDIUM",
    "created_at": "2026-11-07T10:30:00Z"
  }
]
```

---

## 4. Tableau de bord administrateur

### 4.1 Statistiques globales
**GET** `/dashboard/admin/stats`

**Auth :** Bearer token ou cookie `session` + rôle `ADMIN` ou `SUPER_ADMIN`

**Response 200 :**
```json
{
  "users": { "total": 150, "active": 142 },
  "analyses": {
    "total": 5000,
    "today": 42,
    "by_classification": { "CLEAN": 2000, "SUSPICIOUS": 1500, "CRITICAL": 1500 },
    "average_score": 42.5
  },
  "quota_usage": { "total_analyses_today": 120, "active_users_today": 35 }
}
```

---

### 4.2 Lister utilisateurs
**GET** `/dashboard/admin/users?limit=50&offset=0&role=USER&is_active=true`

**Auth :** Admin requis

**Paramètres :**
- `limit` : 1-200 (défaut 50)
- `offset` : ≥0 (défaut 0)
- `role` : `USER` | `ADMIN` | `SUPER_ADMIN` (optionnel)
- `is_active` : `true` | `false` (optionnel)

**Response 200 :**
```json
[
  {
    "id": "uuid",
    "email": "user@example.com",
    "role": "USER",
    "is_active": true,
    "is_test_account": false,
    "created_at": "2026-11-01T10:00:00Z",
    "last_login_at": "2026-11-07T09:00:00Z",
    "failed_login_attempts": 0
  }
]
```

---

### 4.3 Détail utilisateur
**GET** `/dashboard/admin/users/{user_id}`

**Auth :** Admin requis

**Response 200 :**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "role": "USER",
  "is_active": true,
  "is_test_account": false,
  "created_at": "2026-11-01T10:00:00Z",
  "last_login_at": "2026-11-07T09:00:00Z",
  "failed_login_attempts": 0,
  "analyses_count": 42,
  "total_quota_used": 150
}
```

---

### 4.4 Modifier utilisateur
**PATCH** `/dashboard/admin/users/{user_id}`

**Auth :** Admin requis + `X-CSRF-Token`

**Request :**
```json
{
  "is_active": false,
  "role": "ADMIN"
}
```

**Règles :**
- `is_active` : modifiable par tout admin
- `role` : modifiable seulement par `SUPER_ADMIN`
- Un `SUPER_ADMIN` ne peut pas se auto-rétrograder

**Response 200 :**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "role": "ADMIN",
  "is_active": false
}
```

**Erreurs :**
- `400` : Tentative d'auto-rétrogradation SUPER_ADMIN
- `404` : Utilisateur introuvable

---

### 4.5 Logs d'activité
**GET** `/dashboard/admin/activity?limit=100&offset=0&event_type=LOGIN`

**Auth :** Admin requis

**Paramètres :**
- `limit` : 1-500 (défaut 100)
- `offset` : ≥0 (défaut 0)
- `event_type` : filtre optionnel

**Response 200 :**
```json
[
  {
    "id": "uuid",
    "user_id": "uuid",
    "event_type": "LOGIN",
    "event_metadata": { "ip_hash": "abc123", "user_agent": "Mozilla/5.0..." },
    "ip_hash": "abc123",
    "created_at": "2026-11-07T10:30:00Z"
  }
]
```

---

## 5. Codes d'erreur standardisés

| Code | Signification | Corps de réponse |
|---|---|---|
| `400` | Requête invalide | `{ "detail": "..." }` |
| `401` | Non authentifié / Token invalide | `{ "detail": "Could not validate credentials" }` |
| `403` | Accès refusé (rôle insuffisant) | `{ "detail": "Admin access required" }` |
| `404` | Ressource introuvable | `{ "detail": "Analysis not found" }` |
| `409` | Conflit (ex: email existant) | `{ "detail": "Email already registered" }` |
| `422` | Validation échouée | `{ "detail": [{"loc": [...], "msg": "...", "type": "..."}] }` |
| `429` | Quota dépassé | `{ "detail": "Daily analysis quota exceeded" }` + header `Retry-After` |
| `500` | Erreur serveur | `{ "detail": "Internal server error" }` |

---

## 6. Enums et valeurs de référence

### ContentType
`SMS` | `MESSAGE` | `EMAIL` | `URL`

### AnalysisStatus
`COMPLETED` | `PARTIAL` | `FAILED`

### Classification
`CLEAN` (0-39) | `SUSPICIOUS` (40-69) | `CRITICAL` (70-100)

### ReliabilityLevel
`LOW` | `MEDIUM` | `HIGH`

### AssessmentStatus
`CONCLUSIVE` | `INCONCLUSIVE`

### IndicatorNature
`PROVIDER_SIGNAL` | `STRUCTURAL_SIGNAL` | `HEURISTIC_DETECTION` | `INFORMATIVE_SIGNAL`

### RuleValidationStatus
`VALIDEE` | `PROPOSITION_NON_VALIDEE`

### ExplanationSource
`HERMES` | `TEMPLATE` (actuellement toujours `TEMPLATE`)

### VerificationOutcome
`MALICIOUS` | `SUSPICIOUS` | `CLEAN` | `UNDETERMINED` | `FAILED` | `DISABLED` | `NO_PROVIDER_CONFIGURED`

### UserRole
`USER` | `ADMIN` | `SUPER_ADMIN`

---

## 7. Sécurité frontend

### 7.1 Cookies
| Cookie | HttpOnly | Secure | SameSite | Usage |
|---|---|---|---|---|
| `session` | ✅ | Prod only | Lax | Authentification |
| `csrf_token` | ❌ | Prod only | Lax | Protection CSRF (lecture JS) |
| `refresh_token` | ✅ | Prod only | Lax | Renouvellement token |

### 7.2 Headers requis
- `X-CSRF-Token` : Valeur du cookie `csrf_token` pour toutes les requêtes modifiantes (POST, PATCH, DELETE)
- `Authorization: Bearer <token>` : Alternative aux cookies pour l'API

### 7.3 Stockage tokens
- **Access token** : Mémoire seulement (JS variable), **jamais** localStorage/sessionStorage
- **Refresh token** : Cookie HttpOnly uniquement
- **Ne jamais** logger les tokens

### 7.4 CORS
Origines autorisées (config `PHISHGUARD_CORS_ORIGINS`) :
- `http://localhost:3000` (Create React App)
- `http://localhost:5173` (Vite)
- Ajouter l'URL de production Lovable via variable d'environnement

---

## 8. Limites et quotas

| Paramètre | Défaut | Variable d'env |
|---|---|---|
| Caractères max entrée | 1000 | `PHISHGUARD_MAX_INPUT_CHARS` |
| Caractères max normalisé | 10000 | `PHISHGUARD_MAX_NORMALIZED_CHARS` |
| URLs max par analyse | 10 | `PHISHGUARD_MAX_URLS_PER_ANALYSIS` |
| Analyses/jour/utilisateur | 30 | `PHISHGUARD_MAX_ANALYSES_PER_DAY` |
| Access token TTL | 30 min | `PHISHGUARD_ACCESS_TOKEN_EXPIRE_MINUTES` |
| Refresh token TTL | 7 jours | `PHISHGUARD_REFRESH_TOKEN_EXPIRE_DAYS` |

---

## 9. Versioning

| Composant | Version actuelle |
|---|---|
| API | v1 (`/api/v1`) |
| Scoring | 1.2.0 |
| TemplateExplainer | 1.0.0 |
| Contrat Hermes | 1.3 |

---

## 9. MFA (Admin uniquement)

### 9.1 Initialiser MFA
**POST** `/auth/mfa/setup`

**Auth :** Bearer token ou cookie `session` (rôle `ADMIN` ou `SUPER_ADMIN` requis)

**Request :** `{}` (corps vide)

**Response 200 :**
```json
{
  "secret": "ENCRYPTED_BASE64_STRING",
  "provisioning_uri": "otpauth://totp/PhishGuard%20CI:admin%40example.com?secret=BASE32_SECRET&issuer=PhishGuard%20CI"
}
```

**Description :**
- Génère un nouveau secret TOTP chiffré (Fernet/AES-128-GCM)
- Retourne le secret chiffré (pour stockage côté client si besoin) et l'URI de provisioning pour QR code
- Le secret est stocké chiffré en base, MFA **non activé** tant que `/mfa/verify` n'est pas appelé
- Le secret retourné est déjà chiffré ; le frontend ne doit pas le déchiffrer

**Erreurs :**
- `403` : Rôle insuffisant (USER non autorisé)
- `400` : MFA déjà activé

---

### 9.2 Vérifier code MFA et activer
**POST** `/auth/mfa/verify`

**Auth :** Bearer token ou cookie `session` (rôle `ADMIN` ou `SUPER_ADMIN` requis)

**Request :**
```json
{
  "code": "123456"
}
```

**Response 200 :**
```json
{
  "mfa_enabled": true,
  "message": "MFA enabled successfully"
}
```

**Description :**
- Vérifie le code TOTP (fenêtre de tolérance ±1 step = ±30s)
- Si valide : active MFA, remet compteur d'échecs à 0, supprime verrouillage
- Si invalide : incrémente `failed_mfa_attempts` ; à 5 échecs → `mfa_locked_until = now() + 15 min` (retour `429`)

**Erreurs :**
- `403` : Rôle insuffisant
- `400` : Setup non initié ou MFA déjà activé
- `429` : Compte verrouillé (trop d'échecs, attendre 15 min)
- `401` : Code invalide

---

### 9.3 Désactiver MFA
**POST** `/auth/mfa/disable`

**Auth :** Bearer token ou cookie `session` (rôle `ADMIN` ou `SUPER_ADMIN` requis)

**Request :**
```json
{
  "code": "123456"
}
```

**Response 200 :**
```json
{
  "mfa_enabled": false,
  "message": "MFA disabled successfully"
}
```

**Description :**
- Vérifie le code TOTP avant désactivation
- Si valide : désactive MFA, efface `totp_secret`, remet compteurs à 0
- Si invalide : même logique de verrouillage que `/mfa/verify` (5 essais → 15 min)

**Erreurs :**
- `403` : Rôle insuffisant
- `400` : MFA non activé
- `429` : Compte verrouillé
- `401` : Code invalide

---

## 10. Endpoints résumé

| Méthode | Endpoint | Auth | Rôle | Description |
|---|---|---|---|---|
| POST | `/auth/register` | Non | - | Inscription |
| POST | `/auth/login` | Non | - | Connexion |
| POST | `/auth/logout` | Cookie | User | Déconnexion |
| POST | `/auth/refresh` | Cookie/Header | User | Renouvellement token |
| GET | `/auth/me` | Bearer/Cookie | User | Profil |
| GET | `/auth/me/quota` | Bearer/Cookie | User | Quota |
| DELETE | `/auth/me/sessions` | Cookie+CSRF | User | Révoquer sessions |
| POST | `/auth/mfa/setup` | Bearer/Cookie | Admin | Initialiser MFA (retourne secret + QR URI) |
| POST | `/auth/mfa/verify` | Bearer/Cookie | Admin | Vérifier code et activer MFA |
| POST | `/auth/mfa/disable` | Bearer/Cookie | Admin | Vérifier code et désactiver MFA |
| POST | `/analyses` | Bearer/Cookie+CSRF | User | Créer analyse |
| GET | `/analyses` | Bearer/Cookie | User | Lister analyses |
| GET | `/analyses/{ref}` | Bearer/Cookie | User | Détail analyse |
| DELETE | `/analyses/{ref}` | Bearer/Cookie+CSRF | User | Supprimer analyse |
| GET | `/dashboard/user/stats` | Bearer/Cookie | User | Stats user |
| GET | `/dashboard/user/recent` | Bearer/Cookie | User | Analyses récentes |
| GET | `/dashboard/admin/stats` | Bearer/Cookie | Admin | Stats globales |
| GET | `/dashboard/admin/users` | Bearer/Cookie | Admin | Lister users |
| GET | `/dashboard/admin/users/{id}` | Bearer/Cookie | Admin | Détail user |
| PATCH | `/dashboard/admin/users/{id}` | Bearer/Cookie+CSRF | Admin | Modifier user |
| GET | `/dashboard/admin/activity` | Bearer/Cookie | Admin | Logs activité |

---

*Document généré à partir du code source backend PhishGuard CI v0.1.0*