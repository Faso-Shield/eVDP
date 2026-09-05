# API REST — eVDP

Base : `/api/v1/` · Documentation interactive : `/api/docs/` (Swagger),
`/api/redoc/` · Schéma OpenAPI : `/api/schema/`

---

## 1. Authentification

### Clé d'API (intégration machine)

```http
X-eVDP-Api-Key: evdp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Seul le **hachage SHA-256** de la clé est stocké : la valeur en clair n'est
affichée qu'à la création. Une clé peut être révoquée (`is_active`) ou
expirer (`expires_at`).

Création :

```bash
docker compose exec evdp-web python manage.py shell -c "
from apps.accounts.models import ApiKey, User
from apps.api.authentication import generate_key
raw, prefix, key_hash = generate_key()
user = User.objects.get(email='analyste@csirt.bf')
ApiKey.objects.create(user=user, label='Intégration SIEM', prefix=prefix, key_hash=key_hash)
print('Clé (à conserver, non réaffichée) :', raw)
"
```

### Session

Les appels depuis l'interface web utilisent la session Django et exigent un
jeton CSRF sur les méthodes à état.

---

## 2. Conventions

| Aspect | Règle |
|--------|-------|
| Format | JSON (`application/json`) ; `multipart/form-data` pour les pièces jointes |
| Pagination | `?page=`, `?page_size=` (max 100) |
| Filtres | `?status=`, `?severity=`, `?workflow=`, … |
| Recherche | `?search=` |
| Tri | `?ordering=-created_at` |
| Ressource hors périmètre | **404**, jamais 403 |
| Limitation | 429 avec en-tête `Retry-After` |

**Isolation :** chaque réponse est filtrée par le périmètre de l'appelant.
Un chercheur ne voit que ses dossiers ; une DSI que ceux de ses organisations ;
les rôles nationaux voient l'ensemble.

---

## 3. Rapports et dossiers

### Soumettre un rapport

```http
POST /api/v1/reports/
```

```json
{
  "title": "Injection SQL sur le portail e-Etat civil",
  "product": "Portail e-Etat civil",
  "affected_organization_name": "Ministère de démonstration",
  "program": null,
  "target_url": "https://exemple.gov.bf/recherche",
  "vulnerability_type": "SQLI",
  "cwe": "CWE-89",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "description": "Le paramètre `numero` n'est pas filtré…",
  "steps_to_reproduce": "1. Ouvrir la page\n2. Soumettre `1' AND 1=1--`",
  "impact": "Extraction des données d'état civil.",
  "recommendations": "Utiliser des requêtes paramétrées.",
  "requests_cve": true,
  "wants_credit": true
}
```

**201** — retourne le dossier créé :

```json
{
  "case_id": "EVDP-2026-000001",
  "status": "SUBMITTED",
  "severity": "CRITICAL",
  "cvss_score": "9.8",
  "created_at": "2026-09-05T21:43:55Z"
}
```

Le serveur impose `reporter`, `status`, `source` et la sévérité retenue :
ces champs ne sont pas acceptés depuis le client.

Types de vulnérabilité : `AUTHENTICATION`, `AUTHORIZATION`, `XSS`, `SQLI`,
`SSRF`, `RCE`, `LFI_RFI`, `IDOR`, `CSRF`, `INFO_DISCLOSURE`,
`MISCONFIGURATION`, `CRYPTO`, `BUSINESS_LOGIC`, `API_SECURITY`, `MOBILE`,
`CLOUD`, `NETWORK`, `OTHER`.

### Lister / consulter

```http
GET /api/v1/reports/?status=TRIAGE&severity=CRITICAL&ordering=-priority_score
GET /api/v1/reports/EVDP-2026-000001/
```

### Qualifier (analystes)

```http
PATCH /api/v1/reports/EVDP-2026-000001/
{"severity": "HIGH", "cvss_vector": "CVSS:3.1/...", "cwe": "CWE-89"}
```

Capacité requise : `SET_SEVERITY`.

### Changer de statut

```http
POST /api/v1/reports/EVDP-2026-000001/transition/
{"target_status": "VALIDATED", "comment": "Reproduite en préproduction"}
```

**400** si la transition est interdite par la machine à états.

### Messagerie

```http
GET  /api/v1/reports/EVDP-2026-000001/messages/
POST /api/v1/reports/EVDP-2026-000001/messages/
{"body": "Pouvez-vous préciser la version ?", "confidentiality": "PARTICIPANTS"}
```

Niveaux : `PARTICIPANTS`, `INTERNAL` (rôles nationaux),
`RESTRICTED` (coordination nationale). La lecture est filtrée : un chercheur
ne reçoit jamais les messages internes.

### Pièces jointes

```bash
curl -X POST http://localhost/api/v1/reports/EVDP-2026-000001/attachments/ \
  -H "X-eVDP-Api-Key: evdp_..." \
  -F "file=@capture.png" \
  -F "description=Capture de l'injection"
```

Le téléchargement ne passe **pas** par l'API : il utilise
`/attachments/{uuid}/download/`, qui vérifie les droits et journalise.

---

## 4. Programmes

```http
GET  /api/v1/programs/                    # public
GET  /api/v1/programs/?program_type=BUG_BOUNTY
GET  /api/v1/programs/{slug}/
POST /api/v1/programs/                    # capacité MANAGE_PROGRAM
```

La réponse inclut le périmètre (`scopes`) et la matrice de récompenses
(`reward_tiers`) lorsque le programme en déclare une.

---

## 5. Advisories, organisations, chercheurs

```http
GET /api/v1/advisories/?severity=HIGH
GET /api/v1/advisories/EVDP-ADV-2026-000001/
GET /api/v1/organizations/?sector=HEALTH
GET /api/v1/researchers/
```

Ces endpoints sont **publics en lecture** et ne renvoient que des données
publiables : les advisories non publiés et les profils non publics en sont
absents.

---

## 6. Récompenses

```http
GET /api/v1/bounties/?status=APPROVED
GET /api/v1/bounties/{uuid}/
```

Lecture seule via l'API ; les décisions passent par l'interface, où la
séparation des rôles et la traçabilité sont explicites.

---

## 7. Import CSAF 2.0

```http
POST /api/v1/import/csaf/
```

```json
{
  "organization_slug": "mindemo",
  "program_slug": "programme-national-vdp",
  "document_json": {
    "document": {
      "csaf_version": "2.0",
      "category": "csaf_security_advisory",
      "title": "Advisory éditeur",
      "tracking": {"id": "VENDOR-2026-01"}
    },
    "vulnerabilities": [
      {
        "cve": "CVE-2026-1234",
        "title": "Débordement de tampon",
        "notes": [{"category": "description", "text": "…"}],
        "scores": [{"cvss_v3": {"vectorString": "CVSS:3.1/AV:N/..."}}]
      }
    ]
  }
}
```

**201** : `{"imported": 1, "cases": ["EVDP-2026-000042"]}`

Capacité requise : `IMPORT_CSAF`. La validation est **stricte** : version,
catégorie, présence du titre et du suivi, au moins une vulnérabilité, 50
maximum. Un document invalide est rejeté **sans création partielle**
(transaction atomique).

> L'export CSAF n'est pas implémenté (voir PLAN.md).

---

## 8. Recherche

```http
GET /api/v1/search/?q=EVDP-2026-000001
GET /api/v1/search/?q=CVE-2026-1234
```

Recherche sur identifiant, titre, produit, CVE, CWE, organisation et
programme — dans le périmètre autorisé uniquement.

---

## 9. Limitation de débit

| Portée | Défaut | Variable |
|--------|--------|----------|
| Soumission de rapport | 10 / heure | `THROTTLE_REPORT_SUBMISSION` |
| Lecture anonyme | 60 / heure | `THROTTLE_ANON_READ` |
| Appels authentifiés | 1000 / jour | `THROTTLE_AUTHENTICATED` |

Dépassement : **429** avec `Retry-After`.

En cas d'indisponibilité de Redis, la limitation s'ouvre et l'incident est
journalisé (voir `docs/security.md` §8).

---

## 10. Codes d'erreur

| Code | Signification |
|------|---------------|
| 200 / 201 | Succès |
| 400 | Données invalides (détail par champ) |
| 401 | Authentification requise ou clé invalide |
| 403 | Capacité manquante |
| 404 | Ressource inexistante **ou hors périmètre** |
| 413 | Charge utile trop volumineuse |
| 429 | Limite de débit atteinte |
| 500 | Erreur interne (message neutre, détail journalisé côté serveur) |

---

## 11. Observabilité

```http
GET /health/     # liveness
GET /ready/      # readiness (503 si base ou cache indisponible)
GET /metrics/    # format Prometheus, restreint aux réseaux privés
```
