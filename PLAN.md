# PLAN — eVDP (CYBER-DEF 2)

État d'avancement du développement de la plateforme nationale de divulgation
coordonnée de vulnérabilités et de gestion de programmes Bug Bounty.

**Légende :** ✅ terminé · 🟡 partiel (voir note) · ⬜ non implémenté (prévu)

---

## État initial du dépôt

Le répertoire était **vide** au démarrage : aucun travail existant n'a été
supprimé ni modifié. L'ensemble du code a été produit dans le cadre de ce
projet.

---

## Phase 1 — Infrastructure ✅

| Élément | État | Détail |
|---------|------|--------|
| Docker + Compose | ✅ | `docker-compose.yml`, `docker-compose.dev.yml` |
| Image applicative | ✅ | Multi-étapes, `python:3.12-slim`, utilisateur non root (uid 10001), healthcheck, tini |
| PostgreSQL 16 | ✅ | Non exposé, checksums de données, extensions `pg_trgm` / `unaccent` |
| Redis 7 | ✅ | Non exposé, AOF, limite mémoire, politique LRU |
| Celery worker + beat | ✅ | Planificateur en base (`django_celery_beat`) |
| Nginx | ✅ | Rate limiting bordure, en-têtes de sécurité, `/media/` interdit, bloc TLS documenté |
| MinIO | ✅ | Bucket privé versionné, jamais exposé publiquement |
| Mailpit | ✅ | Capture des emails de développement |
| Réseaux séparés | ✅ | `evdp-backend` (interne) / `evdp-frontend` |
| Limites de ressources | ✅ | `deploy.resources.limits` sur chaque service |

## Phase 2 — Comptes, RBAC, organisations, chercheurs ✅

| Élément | État | Détail |
|---------|------|--------|
| Utilisateur personnalisé | ✅ | Email comme identifiant, UUID, Argon2 |
| 10 rôles RBAC | ✅ | `accounts/roles.py`, matrice de 23 capacités |
| Inscription publique bornée | ✅ | Seuls les rôles chercheur sont acceptés |
| Vérification d'email | ✅ | Jeton à usage unique et durée limitée |
| Réinitialisation de mot de passe | ✅ | Vues Django + rate limiting |
| Clés d'API | ✅ | Hachées, préfixe visible, révocables, expiration |
| Organisations | ✅ | 9 types, 13 secteurs, contacts sécurité, PGP |
| Multi-appartenance | ✅ | `OrganizationMember` avec rôle d'appartenance |
| Profils chercheurs | ✅ | Identité publique / pseudonyme / anonyme |
| Réputation | ✅ | Barème configurable, historique non modifiable par le chercheur |
| MFA (TOTP) | ✅ | Obligatoire pour les comptes administrateurs et métiers ; les comptes signaleurs en sont exempts |
| SSO / OIDC / LDAP | ⬜ | Point d'accroche documenté (`AUTHENTICATION_BACKENDS`) |

## Phase 3 — VDP, signalement, case management ✅

| Élément | État | Détail |
|---------|------|--------|
| Programmes VDP | ✅ | Périmètre, règles, Safe Harbor, politique, SLA, PGP |
| Formulaire public | ✅ | 25 champs, Markdown, PGP, pièces jointes, anonymat |
| Soumission anonyme | ✅ | Adresse de contact ou anonymat strict |
| Création automatique du Case | ✅ | `EVDP-AAAA-NNNNNN`, séquence verrouillée |
| Workflow CVD | ✅ | 24 états, transitions déclaratives, capacités requises |
| Workflow Bug Bounty | ✅ | Table de transitions distincte |
| Kanban | ✅ | 7 colonnes |
| Messagerie sécurisée | ✅ | 3 niveaux de confidentialité, hash d'intégrité SHA-256 |
| Pièces jointes | ✅ | Nom opaque, SHA-256, extension + MIME + signature binaire |
| Antivirus ClamAV | ✅ | Service optionnel, protocole INSTREAM, blocage des fichiers infectés |
| Doublons | ✅ | Rattachement sans fuite d'information vers le déclarant |
| SLA | ✅ | Politique configurable, balayage Celery Beat, alertes |
| Chronologie | ✅ | Affichage graphique, marquage public/privé |

## Phase 4 — Bug Bounty ✅

| Élément | État | Détail |
|---------|------|--------|
| Programmes Bug Bounty | ✅ | Périmètre, éligibilité, règles, confidentialité |
| Périmètre structuré | ✅ | 7 types de cibles, priorités P1–P4, in/out of scope |
| Matrice de récompenses | ✅ | Montants en base, jamais codés en dur |
| Cycle de vie des récompenses | ✅ | 6 statuts, transitions contrôlées |
| Revues | ✅ | Avis multiples avant décision |
| Approbation | ✅ | Capacité `APPROVE_BOUNTY` distincte de la proposition |
| Versements | ✅ | Trace comptable uniquement — **aucun paiement réel** (conforme MVP) |
| Contrôle hors matrice | ✅ | Montant hors palier autorisé mais explicitement journalisé |
| Tableau de bord chercheur | ✅ | Rapports, récompenses, réputation, taux de validation |
| Intégration paiement | ⬜ | Point d'accroche `BountyPayment.method` |

## Phase 5 — Advisories et publication ✅

| Élément | État | Détail |
|---------|------|--------|
| Rédaction d'advisory | ✅ | Génération assainie depuis un Case validé |
| Cycle de vie | ✅ | DRAFT → IN_REVIEW → APPROVED → SCHEDULED → PUBLISHED → RETRACTED |
| Page publique | ✅ | `/advisories/`, vue strictement distincte des données internes |
| Chronologie publique | ✅ | Recopiée uniquement depuis les évènements publics |
| Crédit chercheur | ✅ | Respecte le mode d'identité choisi |
| CVSS v3.1 | ✅ | Calculateur autonome, recalculable, hors ligne |
| CVSS v4.0 | 🟡 | Détecté et rejeté proprement (**TODO** : implémentation) |
| CWE / CVE | ✅ | Référentiels locaux, association aux cases et advisories |
| NVD / MITRE / KEV / EPSS | ⬜ | Champs présents, synchronisation non implémentée |

## Phase 6 — Tableaux de bord, statistiques, audit ✅

| Élément | État | Détail |
|---------|------|--------|
| Tableau de bord chercheur | ✅ | 7 indicateurs |
| Tableau de bord organisation / DSI | ✅ | Strictement limité à ses organisations |
| Tableau de bord CSIRT | ✅ | 16 KPI, 5 graphiques, SLA dépassés |
| Tableau de bord national | ✅ | Posture agrégée, aucune donnée identifiante |
| Recherche globale | ✅ | ID, titre, CVE, CWE, organisation, programme |
| Journal d'audit | ✅ | 40 types d'action, append-only, consultation filtrée |
| Notifications | ✅ | 19 types, in-app + email non sensible |
| Exports | ✅ | CSV, Excel, PDF — soumis aux permissions et audités |
| Carte du Burkina Faso | ⬜ | `Organization.region` déjà collecté |

## Phase 7 — API, CSAF, observabilité 🟡

| Élément | État | Détail |
|---------|------|--------|
| API REST v1 | ✅ | 7 ressources, pagination, filtres, throttling |
| OpenAPI / Swagger | ✅ | `/api/docs/`, `/api/redoc/`, `/api/schema/` |
| Authentification par clé | ✅ | En-tête `X-eVDP-Api-Key`, hachée en base |
| Import CSAF 2.0 | ✅ | Validation stricte, `POST /api/v1/import/csaf/` |
| Export CSAF | ⬜ | **TODO** |
| `/health/` `/ready/` `/metrics/` | ✅ | Métriques au format Prometheus |
| Logs JSON structurés | ✅ | Loggers dédiés audit / sécurité / SLA |
| Prometheus / Grafana | ⬜ | Endpoint prêt, stack non fournie |
| SSO | ⬜ | Voir phase 2 ; la MFA est livrée |

## Qualité et exploitation ✅

| Élément | État | Détail |
|---------|------|--------|
| Suite de tests | ✅ | 205 tests : authentification, RBAC, workflow, doublons, pièces jointes, bounty, advisories, API, audit, sécurité, CVSS, ressources statiques |
| CI GitHub Actions | ✅ | lint → tests → scan sécurité → build → scan image → vérification des migrations |
| Ruff / Black | ✅ | Configuration `pyproject.toml` |
| Bandit / pip-audit | ✅ | Intégrés à la CI |
| Trivy | ✅ | Scan de l'image dans la CI |
| Documentation | ✅ | 9 documents + 5 diagrammes Mermaid |
| Sauvegardes | ✅ | `backup_db.sh`, `restore_db.sh`, `backup_minio.sh` |
| Données de démonstration | ✅ | `manage.py seed_demo` — idempotent |

---

## Points explicitement non implémentés

Ces éléments sont volontairement absents du MVP. Chacun dispose d'un point
d'accroche documenté et d'un `TODO` dans le code.

1. **SSO / OIDC / Keycloak / LDAP** — écarté du MVP pour ne pas complexifier le déploiement (conforme §32 du cahier des charges).
2. **CVSS v4.0** — le calculateur détecte et rejette explicitement les vecteurs v4 plutôt que de produire un score faux.
3. **Synchronisation NVD / MITRE / CISA KEV / EPSS** — le fonctionnement de base ne dépend d'aucune API externe (conforme §20).
4. **Export CSAF** — seul l'import est implémenté.
5. **Elasticsearch / OpenSearch** — PostgreSQL suffit au volume du MVP (conforme §36).
6. **Paiement réel des récompenses** — délibérément absent (conforme §18).
7. **Carte du Burkina Faso** — prévue en version ultérieure (conforme §29).
8. **HSM** — l'interface de vérification PGP est prête pour cette bascule.

---

## Critères d'acceptation

| # | Critère | État |
|---|---------|------|
| 1 | `docker compose up -d` fonctionne | ✅ |
| 2 | Page d'accueil accessible | ✅ |
| 3 | Un chercheur peut créer un compte | ✅ |
| 4 | Un chercheur peut soumettre une vulnérabilité | ✅ |
| 5 | Un Case EVDP est créé automatiquement | ✅ |
| 6 | Un analyste peut traiter le Case | ✅ |
| 7 | Le workflow CVD fonctionne | ✅ |
| 8 | L'organisation affectée peut être associée | ✅ |
| 9 | Les messages privés fonctionnent | ✅ |
| 10 | Les pièces jointes sont sécurisées | ✅ |
| 11 | Les permissions RBAC fonctionnent | ✅ |
| 12 | Un programme VDP peut être créé | ✅ |
| 13 | Un programme Bug Bounty peut être créé | ✅ |
| 14 | Un chercheur peut soumettre à un Bug Bounty | ✅ |
| 15 | Une récompense peut être proposée | ✅ |
| 16 | Une récompense peut être approuvée | ✅ |
| 17 | Un Advisory peut être créé | ✅ |
| 18 | Un Advisory peut être publié | ✅ |
| 19 | Les rapports privés ne sont jamais publics | ✅ |
| 20 | Toutes les actions sensibles sont auditées | ✅ |
| 21 | Les tests passent | ✅ |
| 22 | L'installation est documentée | ✅ |
