# Architecture — eVDP

> Plateforme nationale de divulgation coordonnée de vulnérabilités et de
> gestion de programmes Bug Bounty — projet **CYBER-DEF 2**.

Ce document décrit l'architecture retenue, les décisions structurantes et
leurs justifications. Les diagrammes Mermaid sont dans `docs/diagrams/`.

---

## 1. Vue d'ensemble

```
                              INTERNET
                                 │
                          ┌──────▼──────┐
                          │  evdp-nginx │  TLS, en-têtes, rate limiting bordure
                          └──────┬──────┘
                                 │  réseau evdp-frontend
                    ┌────────────▼────────────┐
                    │        evdp-web         │  Django + DRF (Gunicorn)
                    └────┬──────────┬─────────┘
         réseau evdp-backend (interne, non exposé)
              ┌──────────┘          └──────────┐
      ┌───────▼────────┐              ┌────────▼───────┐
      │    evdp-db     │              │   evdp-redis   │
      │  PostgreSQL 16 │              │   cache+broker │
      └────────────────┘              └────────┬───────┘
                                               │
                                 ┌─────────────┴─────────────┐
                          ┌──────▼──────┐            ┌───────▼──────┐
                          │ evdp-worker │            │  evdp-beat   │
                          │   Celery    │            │  planificat. │
                          └──────┬──────┘            └──────────────┘
                                 │
                          ┌──────▼──────┐        ┌──────────────┐
                          │ evdp-minio  │        │ evdp-mailpit │
                          │ pièces      │        │ emails (dev) │
                          │ jointes     │        └──────────────┘
                          └─────────────┘
```

Seul `evdp-nginx` publie un port. PostgreSQL, Redis et MinIO restent
strictement sur le réseau interne `evdp-backend`.

---

## 2. Décisions d'architecture

### DA-1 — Séparation Rapport / Case

Un **rapport** (`reports.VulnerabilityReport`) est la matière brute déclarée.
Un **Case** (`coordination.Case`) est l'objet de traitement : workflow,
sévérité retenue, assignation, échéances, participants.

*Pourquoi :* le rapport doit rester la déclaration originale du chercheur,
non réécrite par les analystes. Toute qualification (sévérité retenue, CWE,
organisation) porte sur le Case. Cela préserve l'intégrité de la preuve et
permet un audit fidèle : « ce qui a été déclaré » ≠ « ce qui a été retenu ».

### DA-2 — Un modèle `Program` unique avec discriminant

Le modèle de données demandé prévoyait `vdp_programs` et `bounty_programs`.
La plateforme utilise un **modèle unique `Program` porteur d'un champ
`program_type` (VDP | BUG_BOUNTY)**.

*Pourquoi :* les deux dispositifs partagent 90 % de leur structure (périmètre,
règles, Safe Harbor, politique de divulgation, SLA, contacts, PGP). Deux
tables quasi identiques auraient imposé des clés étrangères polymorphes
depuis `Case`, `VulnerabilityReport` et `Bounty` — une source classique de
défauts d'intégrité. Seul le volet récompense (`RewardPolicy` /
`RewardTier`) est spécifique au Bug Bounty et vit dans ses propres tables.

La distinction métier reste stricte : le workflow appliqué est déterminé par
`program_type` (voir DA-3), et une récompense est refusée sur un programme VDP.

### DA-3 — Machine à états déclarative

`apps/coordination/workflow.py` déclare deux tables de transitions
(`VDP_TRANSITIONS`, `BOUNTY_TRANSITIONS`) et une table de capacités requises
(`TRANSITION_CAPABILITIES`). `check_transition()` est le seul point de
décision.

*Pourquoi :* une machine à états déclarative est testable exhaustivement et
lisible par un auditeur non développeur. Aucune transition n'est possible sans
y figurer explicitement — l'interdit est le défaut.

### DA-4 — Isolation au niveau du queryset

`Case.objects.visible_to(user)` implémente l'isolation. Toutes les vues, tous
les sélecteurs et tous les endpoints API partent de ce queryset.

*Pourquoi :* concentrer la décision d'accès en un seul endroit rend
l'exhaustivité vérifiable. Un contrôle par vue serait oublié tôt ou tard. Une
seconde barrière objet (`Case.is_visible_to()`) couvre les accès unitaires.

### DA-5 — Clés primaires UUID

Tous les modèles métier utilisent des UUID. Les identifiants lisibles
(`EVDP-2026-000001`, `EVDP-ADV-2026-000001`) servent l'usage humain.

*Pourquoi :* les identifiants séquentiels facilitent l'énumération. Les
identifiants lisibles restent séquentiels par nécessité opérationnelle, mais
chaque accès est contrôlé et un accès non autorisé retourne **404, pas 403** —
un 403 confirmerait l'existence du dossier.

### DA-6 — Advisory comme objet distinct

L'advisory n'est pas une projection calculée du Case : c'est un objet éditorial
créé explicitement par un analyste, dont seuls des champs non sensibles sont
pré-remplis (jamais le PoC, ni les étapes de reproduction, ni l'URL cible), et
dont la chronologie publique est recopiée uniquement depuis les évènements
marqués `is_public`.

*Pourquoi :* Principe 6 — la publication est une décision humaine. Aucune
génération automatique ne peut faire fuiter une donnée interne.

### DA-7 — Journal d'audit append-only

`AuditLog` refuse `save()` sur une entrée existante, `delete()` et
`QuerySet.delete()`. L'administration Django est en lecture seule.

*Pourquoi :* un journal modifiable n'a aucune valeur probante. Les refus
d'accès sont journalisés **hors transaction** afin qu'un rollback ne les
efface pas (voir `coordination.services.transition_case`).

### DA-8 — Rate limiting résilient (fail-open)

La limitation de débit s'appuie sur Redis. Si Redis devient indisponible, la
limitation s'ouvre et l'incident est journalisé en `WARNING` sur le logger
`evdp.security`, au lieu de rendre l'API indisponible.

*Compromis assumé :* une panne de cache dégrade la protection anti-abus mais
ne coupe pas le canal national de signalement. La supervision doit alerter sur
`cache_unavailable` / `throttle_backend_unavailable`. Voir `docs/security.md`.

### DA-9 — Aucune clé privée côté serveur

Seules des clés publiques armurées sont stockées. `apps/core/pgp.py` refuse
tout bloc contenant une clé privée (PGP, RSA, OpenSSH). La vérification
cryptographique est déléguée à un backend optionnel (`python-gnupg`), derrière
une interface stable permettant une bascule vers un HSM sans changement
d'appelant.

### DA-10 — Pièces jointes : nom opaque et service dédié

Le nom de fichier utilisateur n'est jamais un chemin serveur. Le stockage
utilise un UUID. Aucun accès direct : Nginx renvoie 404 sur `/media/`, et le
téléchargement passe par une vue qui vérifie les droits sur le Case et
journalise l'accès.

---

## 3. Organisation applicative

```
apps/
├── core/            Socle : modèles de base, middlewares sécurité, logs JSON,
│                    rate limiting, PGP, markdown assaini, pages publiques,
│                    sondes /health /ready /metrics, commande seed_demo
├── accounts/        Utilisateur, rôles, capacités RBAC, jetons, clés d'API
├── organizations/   Organisations, membres, contacts sécurité
├── researchers/     Profils chercheurs, identité, réputation
├── programs/        Programmes VDP et Bug Bounty, périmètres, règles,
│                    matrice de récompenses
├── vulnerabilities/ CWE, CVE, taxonomies, calculateur CVSS v3.1
├── reports/         Rapport déclaré, formulaire public, service de soumission
├── coordination/    Case management, machine à états, messagerie, SLA,
│                    chronologie, tâches Celery
├── attachments/     Validation, stockage MinIO, téléchargement contrôlé,
│                    analyse antivirus
├── bounty/          Récompenses, revues, versements
├── disclosures/     Advisories : rédaction, cycle de vie, publication
├── notifications/   Notifications internes et emails non sensibles
├── audit/           Journal d'audit immuable
├── dashboard/       Tableaux de bord, recherche globale, exports
├── api/             API REST v1, authentification par clé, pagination
└── csaf/            Import et export CSAF 2.0
```

Chaque application suit la même séparation :

| Fichier          | Rôle |
|------------------|------|
| `models.py`      | Structure et invariants de données |
| `services.py`    | Écritures métier : workflow, audit, notifications |
| `selectors.py`   | Lectures complexes et statistiques |
| `permissions.py` | Décisions d'autorisation |
| `forms.py`       | Validation des entrées web |
| `views.py`       | Orchestration HTTP uniquement |
| `tasks.py`       | Traitements asynchrones Celery |

**Règle :** aucune vue n'écrit directement dans les modèles métier. Toute
écriture sensible passe par un service, qui garantit la cohérence
workflow + audit + notification + SLA.

---

## 4. Modèle de données

### Entités principales

| Table | Modèle | Rôle |
|-------|--------|------|
| `users` | `accounts.User` | Compte, rôle RBAC, PGP |
| `organizations` | `organizations.Organization` | Entité bénéficiaire |
| `organization_members` | `OrganizationMember` | Multi-appartenance |
| `organization_security_contacts` | `SecurityContact` | Contacts publiés |
| `researcher_profiles` | `researchers.ResearcherProfile` | Identité et compteurs |
| `reputation_events` | `ReputationEvent` | Historique de réputation |
| `programs` | `programs.Program` | VDP ou Bug Bounty (DA-2) |
| `program_scopes` | `ProgramScope` | Périmètre inclus/exclu |
| `program_rules` | `ProgramRule` | Règles structurées |
| `reward_policies` / `reward_tiers` | `RewardPolicy` / `RewardTier` | Matrice de montants |
| `vulnerability_reports` | `reports.VulnerabilityReport` | Déclaration brute |
| `cases` | `coordination.Case` | Dossier de traitement |
| `case_status_history` | `CaseStatusHistory` | Historique des transitions |
| `case_assignments` | `CaseAssignment` | Assignations |
| `case_participants` | `CaseParticipant` | Liste blanche d'accès |
| `case_messages` | `CaseMessage` | Messagerie, hash d'intégrité |
| `case_timeline_events` | `CaseTimelineEvent` | Chronologie |
| `sla_policies` / `sla_events` | `SLAPolicy` / `SLAEvent` | Échéances |
| `attachments` | `attachments.Attachment` | Pièces jointes |
| `cwes` / `cves` | `vulnerabilities.CWE` / `CVE` | Référentiels |
| `vulnerability_references` | `VulnerabilityReference` | Références externes |
| `bounties` / `bounty_reviews` / `bounty_payments` | `bounty.*` | Récompenses |
| `advisories` / `advisory_timeline_entries` / `advisory_references` | `disclosures.*` | Publication |
| `notifications` / `email_templates` | `notifications.*` | Notifications |
| `audit_logs` | `audit.AuditLog` | Journal immuable |
| `site_settings` | `core.SiteSetting` | Textes éditables |

### Relations clés

```
Organization 1──n Program 1──n ProgramScope
                     │
                     └──n Case ──1 VulnerabilityReport
                          │
                          ├──n CaseMessage ──n Attachment
                          ├──n CaseTimelineEvent
                          ├──n SLAEvent
                          ├──n CaseParticipant ──1 User
                          ├──1 Bounty ──n BountyReview / BountyPayment
                          └──n Advisory ──n AdvisoryTimelineEntry
```

Un Case pointe vers son doublon éventuel (`duplicate_of`, auto-référence).

---

## 5. RBAC

Le rôle est **persisté en base** et jamais lu depuis le client. Chaque rôle
projette un ensemble de **capacités** (`accounts/roles.py`), et toute décision
passe par `user.has_capability(...)`.

| Rôle | Portée | Capacités notables |
|------|--------|--------------------|
| `SUPER_ADMIN` | Nationale | Toutes |
| `NATIONAL_COORDINATOR` | Nationale | Publication, approbation de récompense, audit |
| `CSIRT_ANALYST` | Nationale | Triage, sévérité, rédaction d'advisory, proposition de récompense |
| `TRIAGER` | Nationale | Triage, sévérité |
| `AUDITOR` | Nationale, **lecture seule** | Consultation, audit, exports |
| `DSI_ADMIN` | Ses organisations | Cases de son périmètre, programmes, remédiation |
| `ORGANIZATION_MANAGER` | Ses organisations | Idem + gestion de l'organisation |
| `SECURITY_RESEARCHER` | Ses rapports | Soumission |
| `BUG_BOUNTY_RESEARCHER` | Ses rapports | Soumission |
| `PUBLIC_USER` | Ses rapports | Soumission |

Seuls `SECURITY_RESEARCHER` et `BUG_BOUNTY_RESEARCHER` sont accessibles à
l'inscription publique (`SELF_SERVICE_ROLES`) ; tout autre rôle soumis par un
client est rejeté.

---

## 6. Flux applicatifs

### Soumission (VDP ou Bug Bounty)

```
Formulaire / API / CSAF
   → validation (forms.py | serializers.py)
   → reports.services.submit_report()
        ├── report.full_clean()  ← règles du modèle, pour les trois chemins
        ├── crée VulnerabilityReport (privé)
        ├── crée Case (statut SUBMITTED, workflow déduit du programme)
        ├── ouvre la chronologie
        ├── rattache déclarant + contacts de l'organisation
        ├── planifie les SLA (accusé de réception, triage)
        ├── journalise REPORT_SUBMITTED + CASE_CREATED
        └── notifie l'équipe de triage et accuse réception au déclarant
```

**`Model.clean()` ne s'exécute pas tout seul.** Seul un `ModelForm` l'appelle,
via son `_post_clean` : un `ModelSerializer` DRF, un import et un
`objects.create()` l'ignorent. Une règle métier posée sur un modèle ne vaut
donc que pour le formulaire web, sauf à être relayée explicitement. Deux
relais existent, à tenir à jour quand un chemin d'écriture s'ajoute :

| Modèle | Relais | Couvre |
|--------|--------|--------|
| `VulnerabilityReport` | `submit_report()` | web, API, import CSAF |
| `Program` | `ProgramWriteSerializer.validate()` | API (le formulaire y passe déjà) |

`Bounty` valide déjà dans `bounty.services`. `Organization`, `SecurityContact`
et `RewardTier` n'ont pas d'autre chemin d'écriture que leur `ModelForm`.

### Transition de statut

```
coordination.services.transition_case()
   ├── check_transition()  ← hors transaction, refus audité durablement
   └── _apply_transition() ← atomique
        ├── met à jour statut et horodatages
        ├── écrit CaseStatusHistory + CaseTimelineEvent
        ├── ouvre/solde les échéances SLA
        ├── recalcule le score de priorité
        ├── journalise STATUS_CHANGED
        ├── notifie déclarant et participants
        └── attribue la réputation à la validation
```

### Publication

```
Case validé
   → disclosures.services.create_advisory_from_case()   (brouillon assaini)
   → relecture → APPROVED
   → publish_advisory()   ← capacité PUBLISH_ADVISORY exigée
        ├── exige un résumé public non vide
        ├── horodate la publication
        ├── journalise ADVISORY_PUBLISHED
        └── notifie le chercheur
```

---

## 7. Sécurité — vue d'architecture

| Couche | Mesures |
|--------|---------|
| Bordure (Nginx) | TLS, HSTS, rate limiting, `server_tokens off`, `/media/` interdit, `/metrics/` restreint aux réseaux privés |
| Transport | Cookies `Secure`+`HttpOnly`+`SameSite`, `SECURE_PROXY_SSL_HEADER` |
| Application | CSP, Permissions-Policy, `X-Frame-Options: DENY`, CSRF, `no-store` sur les pages sensibles |
| Authentification | Argon2, validateurs (12 caractères min.), rate limiting, vérification d'email, TOTP obligatoire hors comptes signaleurs |
| Autorisation | RBAC par capacités, isolation queryset, 404 au lieu de 403 |
| Données | Markdown assaini (bleach), ORM paramétré, pas de mass assignment (champs explicites) |
| Fichiers | Extension + MIME + signature binaire, taille bornée, nom opaque, SHA-256, antivirus optionnel |
| Traçabilité | Journal append-only, refus audités, secrets caviardés |

Voir `docs/security.md` pour le détail et la correspondance OWASP.

---

## 8. Observabilité

| Endpoint | Usage |
|----------|-------|
| `/health/` | Liveness — le processus répond |
| `/ready/` | Readiness — base et cache disponibles (503 sinon) |
| `/metrics/` | Métriques Prometheus, restreint aux réseaux privés |

Les journaux sont émis en **JSON structuré** (`apps/core/logging.py`) sur
`stdout`, prêts pour une collecte Loki/ELK. Loggers dédiés : `evdp.audit`,
`evdp.security`, `evdp.sla`, `evdp.api`.

---

## 9. Extensions prévues

| Sujet | État | Point d'accroche |
|-------|------|------------------|
| SSO / OIDC / Keycloak / LDAP | Non implémenté | `AUTHENTICATION_BACKENDS` |
| HSM pour PGP | Interface prête | `core/pgp.py::verify_signature` |
| CVSS v4.0 | Détecté et rejeté proprement | `vulnerabilities/cvss.py` |
| Synchronisation NVD / MITRE / KEV / EPSS | Champs présents | `CVE.in_cisa_kev`, `epss_score`, `last_synced_at` |
| Product tree CSAF complexe | Import : produit simple uniquement | `apps/csaf/services.py` |
| Elasticsearch / OpenSearch | Non requis au MVP | `coordination/selectors.py::search_cases` |
| Carte du Burkina Faso | Non implémenté | `Organization.region` déjà collecté |
| Paiement réel des récompenses | Volontairement absent | `bounty.BountyPayment.method` |

Chaque point est repéré par un commentaire `TODO` dans le code correspondant.

---

## 10. Correctifs de robustesse issus de la validation

Les points suivants ont été identifiés en exécutant réellement la plateforme
et sont couverts par des tests de non-régression.

| Problème | Impact | Correctif |
|----------|--------|-----------|
| L'audit d'une transition refusée était annulé par le rollback de la transaction | Perte de la trace d'une tentative d'accès illégitime | La vérification est faite **hors transaction** ; seule l'application est atomique (`transition_case` / `_apply_transition`) |
| `web` et `beat` lançaient `migrate` simultanément au démarrage | Collision sur la création des tables, pile indémarrable | Seul le rôle `web` migre ; `beat` attend le schéma via `migrate --check` |
| Nginx résolvait l'IP de `evdp-web` une seule fois au démarrage | 502 après tout redémarrage du conteneur applicatif | Résolveur DNS Docker interrogé à l'exécution (`resolver 127.0.0.11` + `proxy_pass` via variable) |
| Une ressource statique manquante faisait échouer le manifeste en production | Erreur 500 sur **toutes** les pages HTML | Ressource ajoutée + test vérifiant que chaque `{% static %}` des gabarits est résolvable |
| `{{ x.organization.acronym\|default:x.organization.name }}` | Erreur 500 dès qu'un dossier n'avait pas d'organisation (les arguments de filtre Django sont résolus strictement) | Remplacé par `{% firstof %}` ; test de rendu avec un dossier sans organisation |
| Une panne de Redis rendait toute l'API indisponible | Canal national de signalement coupé | Limitation de débit en *fail-open* avec journalisation `evdp.security` (voir DA-8) |
| Liens des emails construits depuis `ALLOWED_HOSTS` | URL erronée dans les notifications | Variable `SITE_BASE_URL` explicite |
| Schéma OpenAPI : collisions d'énumérations et authentification non décrite | Documentation d'API inexploitable | `ENUM_NAME_OVERRIDES`, `@extend_schema_field` et `OpenApiAuthenticationExtension` pour la clé d'API |

`manage.py check --deploy` ne remonte plus que deux avertissements, tous deux
attendus tant que le TLS n'est pas activé (`SECURE_HSTS_SECONDS`,
`SECURE_SSL_REDIRECT`) — voir la checklist de `docs/deployment.md`.
