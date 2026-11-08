# Exemples API — PhishGuard CI

**Version :** 1.0  
**Date :** 7 novembre 2026  
**Base URL :** `https://api.phishguard-ci.example.com/api/v1`

---

## 1. Authentification

### 1.1 Inscription

**Requête :**
```bash
curl -X POST https://api.phishguard-ci.example.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "jean.dupont@example.com",
    "password": "MonMotDePasseSecurise123!"
  }'
```

**Réponse 201 :**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "email": "jean.dupont@example.com",
  "role": "USER",
  "is_active": true,
  "is_test_account": false,
  "created_at": "2026-11-07T10:30:00.123456Z",
  "last_login_at": null
}
```

**Erreur 409 :**
```json
{ "detail": "Email already registered" }
```

---

### 1.2 Connexion

**Requête :**
```bash
curl -X POST https://api.phishguard-ci.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  --cookie-jar cookies.txt \
  -d '{
    "email": "jean.dupont@example.com",
    "password": "MonMotDePasseSecurise123!"
  }'
```

**Réponse 200 :**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhMWIyYzNkNC1lNWY2LTc4OTAtYWJjZC1lZjEyMzQ1Njc4OTAiLCJyb2xlIjoiVVNFUiIsImV4cCI6MTczMTAwMDAwMCwidHlwZSI6ImFjY2VzcyJ9.xyz",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhMWIyYzNkNC1lNWY2LTc4OTAtYWJjZC1lZjEyMzQ1Njc4OTAiLCJleHAiOjE3MzE1MDAwMDAsInR5cGUiOiJyZWZyZXNoIn0.abc",
  "token_type": "bearer",
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "email": "jean.dupont@example.com",
    "role": "USER",
    "is_active": true,
    "is_test_account": false,
    "created_at": "2026-11-07T10:30:00.123456Z",
    "last_login_at": "2026-11-07T10:30:00.123456Z"
  }
}
```

**Cookies reçus :**
```
session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1800
csrf_token=xyz789; Secure; SameSite=Lax; Path=/; Max-Age=1800
refresh_token=refresh123; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800
```

**Erreur 401 :**
```json
{ "detail": "Invalid credentials" }
```

---

### 1.3 Connexion admin (avec MFA)

```bash
curl -X POST https://api.phishguard-ci.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  --cookie-jar cookies.txt \
  -d '{
    "email": "admin@phishguard-ci.example.com",
    "password": "AdminPassword123!",
    "mfa_code": "123456"
  }'
```

---

### 1.4 Déconnexion

```bash
curl -X POST https://api.phishguard-ci.example.com/api/v1/auth/logout \
  --cookie cookies.txt \
  --cookie-jar cookies.txt
```

**Réponse 200 :**
```json
{ "message": "Logged out successfully" }
```

---

### 1.5 Renouvellement access token

**Option A : Via cookie refresh_token (recommandé)**
```bash
curl -X POST https://api.phishguard-ci.example.com/api/v1/auth/refresh \
  --cookie cookies.txt \
  --cookie-jar cookies.txt
```

**Option B : Via header Authorization**
```bash
curl -X POST https://api.phishguard-ci.example.com/api/v1/auth/refresh \
  -H "Authorization: Bearer <refresh_token>"
```

**Réponse 200 :**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

---

### 1.6 Profil utilisateur

```bash
curl -X GET https://api.phishguard-ci.example.com/api/v1/auth/me \
  -H "Authorization: Bearer <access_token>"
# ou avec cookies
curl -X GET https://api.phishguard-ci.example.com/api/v1/auth/me \
  --cookie cookies.txt
```

**Réponse 200 :**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "email": "jean.dupont@example.com",
  "role": "USER",
  "is_active": true,
  "is_test_account": false,
  "created_at": "2026-11-07T10:30:00.123456Z",
  "last_login_at": "2026-11-07T10:30:00.123456Z"
}
```

---

### 1.7 Statut quota

```bash
curl -X GET https://api.phishguard-ci.example.com/api/v1/auth/me/quota \
  -H "Authorization: Bearer <access_token>"
```

**Réponse 200 :**
```json
{
  "max_per_day": 30,
  "used_today": 7,
  "remaining": 23,
  "reset_at": "2026-11-07T23:59:59.999999Z"
}
```

---

### 1.8 Révocation toutes sessions

```bash
curl -X DELETE https://api.phishguard-ci.example.com/api/v1/auth/me/sessions \
  -H "Authorization: Bearer <access_token>" \
  -H "X-CSRF-Token: <csrf_token_from_cookie>" \
  --cookie cookies.txt \
  --cookie-jar cookies.txt
```

**Réponse 200 :**
```json
{ "message": "Revoked 3 sessions" }
```

---

## 2. Analyse

### 2.1 Créer une analyse (MESSAGE)

```bash
curl -X POST https://api.phishguard-ci.example.com/api/v1/analyses \
  -H "Authorization: Bearer <access_token>" \
  -H "X-CSRF-Token: <csrf_token>" \
  -H "Content-Type: application/json" \
  --cookie cookies.txt \
  -d '{
    "content": "Urgent : votre compte Orange Money sera bloqué sous 24h. Cliquez sur http://192.168.1.1/paiement pour valider votre code PIN.",
    "content_type": "MESSAGE"
  }'
```

**Réponse 201 :**
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
      "evidence_snippet": "votre code PIN",
      "validation_status": "VALIDEE"
    },
    {
      "code": "URGENCY_PRESSURE",
      "category": "URGENCY_MANIPULATION",
      "nature": "HEURISTIC_DETECTION",
      "label": "Menace de blocage sous délai court",
      "points_awarded": 15,
      "evidence_snippet": "bloqué sous 24h",
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

---

### 2.2 Créer une analyse (SMS)

```bash
curl -X POST https://api.phishguard-ci.example.com/api/v1/analyses \
  -H "Authorization: Bearer <access_token>" \
  -H "X-CSRF-Token: <csrf_token>" \
  -H "Content-Type: application/json" \
  --cookie cookies.txt \
  -d '{
    "content": "Orange Money: Votre code de validation est 1234. Ne le communiquez a personne.",
    "content_type": "SMS"
  }'
```

---

### 2.3 Créer une analyse (URL seule)

```bash
curl -X POST https://api.phishguard-ci.example.com/api/v1/analyses \
  -H "Authorization: Bearer <access_token>" \
  -H "X-CSRF-Token: <csrf_token>" \
  -H "Content-Type: application/json" \
  --cookie cookies.txt \
  -d '{
    "content": "https://phishing-example.top/login?token=abc123",
    "content_type": "URL"
  }'
```

---

### 2.4 Analyse avec contenu trop long (erreur 422)

```bash
curl -X POST https://api.phishguard-ci.example.com/api/v1/analyses \
  -H "Authorization: Bearer <access_token>" \
  -H "X-CSRF-Token: <csrf_token>" \
  -H "Content-Type: application/json" \
  --cookie cookies.txt \
  -d '{
    "content": "' + 'x'.repeat(2000) + '",
    "content_type": "MESSAGE"
  }'
```

**Erreur 422 :**
```json
{
  "detail": "Content exceeds maximum length of 1000 characters"
}
```

---

### 2.5 Lister les analyses

```bash
curl -X GET "https://api.phishguard-ci.example.com/api/v1/analyses?limit=10&offset=0" \
  -H "Authorization: Bearer <access_token>"
```

**Réponse 200 :**
```json
[
  {
    "analysis_ref": "c4d2e1a9-7b3f-4e8a-9f12-3456789abcde",
    "status": "PARTIAL",
    "score": 85,
    "classification": "CRITICAL",
    "reliability_level": "MEDIUM",
    "assessment_status": "CONCLUSIVE",
    "indicators": [...],
    "explanation": "Ce message présente un niveau de risque CRITICAL...",
    "explanation_source": "TEMPLATE",
    "template_version": "1.0.0",
    "scoring_version": "1.2.0"
  },
  {
    "analysis_ref": "d5e3f2b0-8c4a-5f9b-0a13-4567890bcdef",
    "status": "COMPLETED",
    "score": 15,
    "classification": "CLEAN",
    "reliability_level": "HIGH",
    "assessment_status": "CONCLUSIVE",
    "indicators": [],
    "explanation": "Ce message présente un niveau de risque FAIBLE...",
    "explanation_source": "TEMPLATE",
    "template_version": "1.0.0",
    "scoring_version": "1.2.0"
  }
]
```

---

### 2.6 Obtenir une analyse spécifique

```bash
curl -X GET "https://api.phishguard-ci.example.com/api/v1/analyses/c4d2e1a9-7b3f-4e8a-9f12-3456789abcde" \
  -H "Authorization: Bearer <access_token>"
```

**Note :** L'explication est régénérée avec la version actuelle du template (D20).

---

### 2.7 Supprimer une analyse

```bash
curl -X DELETE "https://api.phishguard-ci.example.com/api/v1/analyses/c4d2e1a9-7b3f-4e8a-9f12-3456789abcde" \
  -H "Authorization: Bearer <access_token>" \
  -H "X-CSRF-Token: <csrf_token>" \
  --cookie cookies.txt
```

**Réponse 204** (vide)

---

### 2.8 Quota dépassé (erreur 429)

```json
{
  "detail": "Daily analysis quota exceeded"
}
```
**Header :** `Retry-After: 12345` (secondes jusqu'au reset minuit UTC)

---

## 3. Tableau de bord utilisateur

### 3.1 Statistiques

```bash
curl -X GET https://api.phishguard-ci.example.com/api/v1/dashboard/user/stats \
  -H "Authorization: Bearer <access_token>"
```

**Réponse :**
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

```bash
curl -X GET "https://api.phishguard-ci.example.com/api/v1/dashboard/user/recent?limit=5" \
  -H "Authorization: Bearer <access_token>"
```

**Réponse :**
```json
[
  {
    "analysis_ref": "c4d2e1a9-7b3f-4e8a-9f12-3456789abcde",
    "content_type": "MESSAGE",
    "status": "PARTIAL",
    "score": 85,
    "classification": "CRITICAL",
    "reliability_level": "MEDIUM",
    "created_at": "2026-11-07T10:30:00.123456Z"
  }
]
```

---

## 4. Administration

### 4.1 Statistiques globales (Admin requis)

```bash
curl -X GET https://api.phishguard-ci.example.com/api/v1/dashboard/admin/stats \
  -H "Authorization: Bearer <admin_access_token>"
```

**Réponse :**
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

### 4.2 Lister utilisateurs (Admin requis)

```bash
curl -X GET "https://api.phishguard-ci.example.com/api/v1/dashboard/admin/users?limit=20&offset=0&role=USER&is_active=true" \
  -H "Authorization: Bearer <admin_access_token>"
```

**Réponse :**
```json
[
  {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "email": "user@example.com",
    "role": "USER",
    "is_active": true,
    "is_test_account": false,
    "created_at": "2026-11-01T10:00:00.123456Z",
    "last_login_at": "2026-11-07T09:00:00.123456Z",
    "failed_login_attempts": 0
  }
]
```

---

### 4.3 Modifier utilisateur (Admin requis)

```bash
curl -X PATCH https://api.phishguard-ci.example.com/api/v1/dashboard/admin/users/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "X-CSRF-Token: <csrf_token>" \
  -H "Content-Type: application/json" \
  --cookie cookies.txt \
  -d '{
    "is_active": false,
    "role": "ADMIN"
  }'
```

**Réponse 200 :**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "email": "user@example.com",
  "role": "ADMIN",
  "is_active": false
}
```

---

### 4.4 Logs d'activité (Admin requis)

```bash
curl -X GET "https://api.phishguard-ci.example.com/api/v1/dashboard/admin/activity?limit=50&event_type=LOGIN" \
  -H "Authorization: Bearer <admin_access_token>"
```

**Réponse :**
```json
[
  {
    "id": "uuid",
    "user_id": "uuid",
    "event_type": "LOGIN",
    "event_metadata": { "ip_hash": "abc123", "user_agent": "Mozilla/5.0..." },
    "ip_hash": "abc123",
    "created_at": "2026-11-07T10:30:00.123456Z"
  }
]
```

---

## 5. Erreurs courantes

### 5.1 400 Bad Request
```json
{ "detail": "Invalid request data" }
```

### 5.2 401 Unauthorized
```json
{ "detail": "Could not validate credentials" }
```
**Action :** Tentative refresh token → redirection `/login`

### 5.3 403 Forbidden
```json
{ "detail": "Admin access required" }
```
**Action :** Rediriger vers `/dashboard`

### 5.4 404 Not Found
```json
{ "detail": "Analysis not found" }
```

### 5.5 409 Conflict
```json
{ "detail": "Email already registered" }
```

### 5.6 422 Unprocessable Entity
```json
{
  "detail": [
    {
      "loc": ["body", "content"],
      "msg": "ensure this value has at least 1 characters",
      "type": "value_error.any_str.min_length"
    }
  ]
}
```

### 5.7 429 Too Many Requests
```json
{ "detail": "Daily analysis quota exceeded" }
```
**Header :** `Retry-After: 3600`

### 5.8 500 Internal Server Error
```json
{ "detail": "Internal server error" }
```

---

## 6. Headers de sécurité attendus

**Réponses backend :**
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains (prod only)
```

---

## 7. Versioning

| Header | Valeur |
|---|---|
| `X-API-Version` | `v1` |
| `X-Scoring-Version` | `1.2.0` |
| `X-Template-Version` | `1.0.0` |
| `X-Contract-Version` | `1.3` |

---

*Exemples générés pour PhishGuard CI Backend v0.1.0*