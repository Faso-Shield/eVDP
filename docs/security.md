# Sécurité — eVDP

eVDP centralise des vulnérabilités **non corrigées** affectant des services
publics. Sa compromission équivaudrait à une compromission nationale. Ce
document décrit le modèle de menaces, les contrôles en place et les
compromis assumés.

---

## 1. Modèle de menaces

| Menace | Impact | Contrôles |
|--------|--------|-----------|
| Accès non autorisé à un rapport non corrigé | Exploitation par un tiers | Isolation queryset, 404 au lieu de 403, audit des refus |
| Élévation de privilèges d'un chercheur | Accès à l'ensemble des dossiers | Rôle non modifiable par l'utilisateur, capacités vérifiées côté serveur |
| Exfiltration d'une preuve de concept | Arme prête à l'emploi | Pièces jointes hors web root, téléchargement contrôlé et journalisé |
| Publication prématurée | Fenêtre d'exploitation ouverte | Aucune publication automatique, advisory distinct, capacité dédiée |
| Compromission du compte d'un analyste | Accès étendu | Argon2, rate limiting, audit, MFA prête |
| Fuite d'identité d'un chercheur | Représailles | Modes public/pseudonyme/anonyme respectés partout |
| XSS stocké via un rapport | Vol de session d'analyste | Markdown assaini (bleach), CSP, uploads HTML/SVG refusés |
| Fichier malveillant en pièce jointe | Compromission d'un poste | Extension + MIME + signature binaire, ClamAV optionnel |
| Abus du canal de signalement | Saturation du CSIRT | Rate limiting applicatif et bordure, CAPTCHA configurable |
| Altération des traces | Perte de valeur probante | Journal append-only, refus journalisés hors transaction |

---

## 2. Authentification

- **Argon2** comme algorithme de hachage principal (`PASSWORD_HASHERS`).
- Longueur minimale de **12 caractères** et validateurs Django standards.
- Identifiant = adresse email, vérifiée par jeton à usage unique et durée limitée.
- Rate limiting sur connexion, inscription et réinitialisation.
- Réponses **neutres** : l'inscription ne confirme jamais l'existence d'un compte.
- Sessions : `HttpOnly`, `SameSite=Lax`, `Secure` en production, expiration à la fermeture du navigateur, durée 8 h.
- Clés d'API : seul le **hachage SHA-256** est stocké ; la valeur en clair n'est affichée qu'une fois.

**MFA :** les champs `mfa_enabled` / `mfa_secret` et la dépendance `pyotp`
sont en place. Le parcours d'activation n'est **pas** implémenté (TODO).

---

## 3. Autorisation

### Principe

Le rôle provient **exclusivement de la base**. Aucune valeur envoyée par le
client n'accorde de privilège. À l'inscription publique, seuls les rôles
chercheur sont acceptés (`SELF_SERVICE_ROLES`).

### Trois barrières

1. **Queryset** — `Case.objects.visible_to(user)` : point unique d'isolation.
2. **Objet** — `Case.is_visible_to(user)` pour les accès unitaires.
3. **Capacité** — `user.has_capability(...)` avant toute action sensible.

### Réponse aux accès refusés

Un accès à un dossier hors périmètre retourne **404**, jamais 403 : un 403
confirmerait l'existence du dossier. Le refus est journalisé avec
`result=DENIED`.

### Confidentialité des messages

| Niveau | Visible par |
|--------|-------------|
| `PARTICIPANTS` | Déclarant, analyste, organisation, coordination |
| `INTERNAL` | Rôles nationaux uniquement |
| `RESTRICTED` | Coordination nationale et administrateurs uniquement |

Le filtrage est appliqué dans `coordination.services.visible_messages()` —
jamais dans le gabarit.

---

## 4. Protection des données

### Rapports

Privés par défaut. Aucun mécanisme ne rend un rapport public. Seul un
**advisory** — objet distinct, rédigé par un analyste — est publiable.

### Advisories

Créés depuis un Case validé, ils ne pré-remplissent **jamais** :
preuve de concept, étapes de reproduction, URL cible, pièces jointes,
messages, identifiant du Case. La chronologie publique est recopiée
uniquement depuis les évènements marqués `is_public`.

Test de non-régression : `tests/test_disclosure.py::test_advisory_does_not_copy_sensitive_case_fields`.

### Doublons

Le déclarant est informé que son rapport est un doublon, sans jamais recevoir
l'identifiant ni le contenu du dossier original.

### Minimisation

- L'IP du déclarant n'est pas conservée en clair : seule une empreinte SHA-256 (`submitter_ip_hash`) sert la détection d'abus.
- Les emails de notification ne contiennent **aucun** détail technique : ils annoncent la disponibilité d'une information dans l'espace authentifié.
- Les métadonnées d'audit caviardent automatiquement toute clé contenant `password`, `token`, `secret`, `key`, `authorization`, `cookie`.

---

## 5. Pièces jointes

Les pièces jointes contiennent des preuves de concept : ce sont les données
les plus sensibles de la plateforme.

| Contrôle | Mise en œuvre |
|----------|---------------|
| Nom de fichier | UUID opaque ; le nom utilisateur n'est qu'une métadonnée d'affichage |
| Extension | Liste blanche **et** liste noire (`exe`, `js`, `php`, `html`, `svg`, …) |
| Type MIME | Vérifié ; types exécutables refusés |
| Signature binaire | `MZ` (PE), `\x7fELF`, `#!/`, magic Java refusés même sous extension inoffensive |
| Taille | Bornée (25 Mo par défaut, configurable) |
| Nombre | Borné par dossier (20 par défaut) |
| Intégrité | SHA-256 conservé |
| Antivirus | Service ClamAV optionnel (INSTREAM) ; un fichier `INFECTED` est définitivement bloqué |
| Accès | `/media/` renvoie 404 sur Nginx ; le téléchargement passe par une vue qui vérifie les droits et journalise |
| Réponse | `application/octet-stream` + `nosniff` + CSP `sandbox` : le navigateur n'interprète jamais le contenu |
| Chiffrement au repos | Assuré au niveau du volume MinIO (voir docs/deployment.md) |

---

## 6. PGP

- **Aucune clé privée n'est stockée**, jamais. Tout bloc contenant `PRIVATE KEY` (PGP, RSA, OpenSSH) est refusé à la validation.
- Seules des clés publiques armurées sont acceptées, avec contrôle de forme et de taille.
- Un rapport peut être transmis sous forme de bloc `PGP MESSAGE` chiffré, stocké tel quel et déchiffré **hors ligne** par l'équipe destinataire.
- La vérification de signature est déléguée à un backend optionnel (`python-gnupg`) derrière une interface stable, permettant une bascule vers un **HSM** sans modifier les appelants.
- En l'absence de backend, le contenu est explicitement considéré comme **non vérifié**.
- Le champ `pgp_payload` est **optionnel et complémentaire**, pas une exigence pour chaque signalement : les autres champs (description, étapes de reproduction, preuve de concept) restent en clair et suffisent pour la grande majorité des rapports. Il n'est destiné qu'au détail qui rendrait la faille immédiatement exploitable s'il fuitait (payload fonctionnel, données réelles extraites, identifiants encore valides) — voir le texte d'aide du formulaire de signalement.
- Le champ `pgp_payload` est un simple texte : il ne chiffre pas les pièces jointes. Celles-ci restent, par défaut, seulement protégées par nom aléatoire, hachage SHA-256 et contrôle d'accès (§5) — pas par un chiffrement de contenu.
- **Une pièce jointe peut néanmoins être protégée individuellement** : si le fichier déposé est lui-même un bloc PGP armuré (chiffré au préalable par le déclarant avec la clé nationale, avant dépôt), `store_attachment()` le détecte (en-tête ET pied de page recherchés sur un échantillon en début et fin de fichier, `apps/attachments/services.py`) et le marque `is_pgp_encrypted=True` — affiché comme tel (badge « 🔒 PGP ») dans le détail du dossier. Un fichier déposé sans ce chiffrement préalable reste lisible par quiconque aurait un accès compromis au stockage.

---

## 7. Défenses web

| Mesure | Détail |
|--------|--------|
| CSP | `default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'` ; en production `script-src 'self'` sans inline |
| HSTS | 1 an, `includeSubDomains`, `preload` (production) |
| X-Frame-Options | `DENY` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | Géolocalisation, micro, caméra, paiement, USB désactivés |
| X-Content-Type-Options | `nosniff` |
| Cross-Origin-Opener-Policy | `same-origin` |
| Cache | `no-store` sur `/dashboard`, `/cases`, `/api`, `/attachments` |
| CSRF | Actif sur toutes les vues à état ; testé |
| XSS | Markdown rendu via bleach, liste blanche de balises, `rel="noopener noreferrer nofollow"` sur les liens externes |
| SQLi | ORM Django exclusivement, aucune requête SQL construite par concaténation |
| Mass assignment | Serializers et formulaires à champs explicites ; les champs de workflow ne sont jamais modifiables par le client |
| SSRF | La plateforme n'effectue aucune requête sortante à partir d'une URL fournie par l'utilisateur |

---

## 8. Limitation de débit

Deux niveaux complémentaires.

**Bordure (Nginx)** — `/login/` 2 r/s, `/register/` 2 r/s, `/report/` 1 r/s,
général 20 r/s, 24 connexions simultanées par IP.

**Application** — compteur à fenêtre dans Redis :

| Portée | Défaut | Variable |
|--------|--------|----------|
| Connexion | 10 / 5 min | `EVDP_RL_LOGIN` |
| Inscription | 5 / heure | `EVDP_RL_REGISTER` |
| Signalement | 10 / heure | `EVDP_RL_REPORT` |
| Réinitialisation | 5 / heure | `EVDP_RL_PASSWORD_RESET` |
| API (soumission) | 10 / heure | `THROTTLE_REPORT_SUBMISSION` |

### Compromis assumé : fail-open

Si Redis devient indisponible, la limitation **s'ouvre** au lieu de bloquer la
plateforme, et l'incident est journalisé en `WARNING` sur le logger
`evdp.security` (`cache_unavailable`, `throttle_backend_unavailable`).

*Justification :* rendre le canal national de signalement indisponible à cause
d'une panne de cache serait un impact plus grave que la dégradation temporaire
de la protection anti-abus. **La supervision doit alerter sur ces deux
évènements** : Nginx reste la seule barrière pendant l'incident.

---

## 9. Journal d'audit

- 40 types d'actions couvrant authentification, cases, messages, pièces jointes, récompenses, advisories, organisations, rôles, exports et imports.
- Chaque entrée : horodatage, acteur (et son email dénormalisé), action, objet, résultat, IP, user-agent, métadonnées.
- **Append-only** : `save()` sur une entrée existante, `delete()` et `QuerySet.delete()` lèvent `NotImplementedError`. L'administration Django est en lecture seule.
- Les **refus** sont journalisés **hors transaction** : un rollback ne peut pas effacer la trace d'une tentative d'accès illégitime.
- Consultation réservée à `SUPER_ADMIN`, `NATIONAL_COORDINATOR`, `AUDITOR`.

---

## 10. Durcissement de l'infrastructure

- Image applicative multi-étapes ; les outils de compilation ne sont pas embarqués.
- Exécution sous l'utilisateur **non privilégié** `evdp` (uid 10001).
- Aucun secret dans les images ni dans le dépôt : tout provient de l'environnement.
- PostgreSQL, Redis et MinIO ne publient **aucun port** ; en développement ils sont liés à `127.0.0.1`.
- Réseaux Docker séparés (`evdp-backend` interne, `evdp-frontend`).
- Healthchecks et limites mémoire sur chaque service.
- Versions d'images explicites (jamais `latest`).
- `server_tokens off` sur Nginx.

---

## 11. Correspondance OWASP Top 10 (2021)

| Risque | Traitement |
|--------|------------|
| A01 Broken Access Control | Isolation queryset + objet + capacité, 404 au lieu de 403, refus audités, tests dédiés |
| A02 Cryptographic Failures | Argon2, TLS, cookies sécurisés, aucune clé privée stockée, SHA-256 d'intégrité |
| A03 Injection | ORM exclusivement, Markdown assaini, validation stricte des entrées |
| A04 Insecure Design | Privé par défaut, machine à états déclarative, séparation proposer/approuver/payer |
| A05 Security Misconfiguration | En-têtes complets, `DEBUG=False`, secrets externalisés, images épinglées |
| A06 Vulnerable Components | `pip-audit` et Trivy en CI, versions figées dans `requirements/` |
| A07 Auth Failures | Rate limiting, verrouillage de compte via limitation, messages neutres, vérification d'email |
| A08 Data Integrity Failures | Hash des messages, audit append-only, dépendances figées |
| A09 Logging Failures | Journal d'audit complet, logs JSON, échecs de connexion et refus tracés |
| A10 SSRF | Aucune requête sortante déclenchée par une URL utilisateur |

---

## 12. Points de vigilance en exploitation

1. **Superviser** `cache_unavailable` et `throttle_backend_unavailable` (fail-open, §8).
2. **Ne jamais** exécuter `seed_demo` en production : il crée des comptes à mot de passe connu.
3. **Activer le TLS** et passer `SECURE_SSL_REDIRECT=True` et `SECURE_HSTS_SECONDS=31536000`.
4. **Restreindre `/metrics/`** — la configuration Nginx fournie le limite déjà aux réseaux privés.
5. **Activer ClamAV** en production : sans lui, les pièces jointes sont marquées `SKIPPED` et restent téléchargeables.
6. **Chiffrer les sauvegardes** : elles contiennent l'intégralité des rapports non corrigés.
7. **Faire tourner les clés d'API** et révoquer celles inutilisées.

---

## 13. Signaler une vulnérabilité sur eVDP

La plateforme publie son propre point de contact machine-lisible :
`/.well-known/security.txt`. Un signalement concernant eVDP lui-même suit
exactement le même processus que tout autre signalement.
