# Administration — eVDP

Guide d'exploitation quotidienne à destination des équipes ANSSI-BF / CSIRT.

---

## 1. Rôles et attributions

| Rôle | Attribué à | Portée |
|------|-----------|--------|
| `SUPER_ADMIN` | Administrateurs plateforme | Tout |
| `NATIONAL_COORDINATOR` | Coordination nationale | Tous les dossiers, publication, approbation des récompenses, audit |
| `CSIRT_ANALYST` | Analystes CSIRT | Triage, qualification, rédaction d'advisory, proposition de récompense |
| `TRIAGER` | Agents de premier niveau | Triage et sévérité uniquement |
| `AUDITOR` | Contrôle interne, inspection | **Lecture seule** + journal d'audit |
| `DSI_ADMIN` | DSI d'administration | Ses organisations |
| `ORGANIZATION_MANAGER` | Responsable d'entité | Ses organisations + gestion |
| `SECURITY_RESEARCHER` | Chercheurs | Ses rapports |
| `BUG_BOUNTY_RESEARCHER` | Chasseurs de bugs | Ses rapports |
| `PUBLIC_USER` | Compte créé sans qualification | Ses rapports |

### Le menu latéral suit les capacités

Le menu de l'espace authentifié n'est pas écrit dans le gabarit : il est
calculé dans `apps/core/navigation.py`, chaque entrée déclarant la capacité
qu'elle exige. Un compte ne voit donc que ce qu'il peut ouvrir, et un titre de
rubrique n'apparaît que si la rubrique a du contenu.

Un compte signaleur s'y réduit à **Tableau de bord**, **Récompenses**,
**Advisories publiés** et **Mon profil**.

`Tableau de bord` n'affiche rien par lui-même : il aiguille vers la vue du
rôle (`apps/core/navigation.py::landing_route`, que la vue d'aiguillage et le
menu lisent tous deux). Une entrée « Vue X » n'est donc listée que si elle
mène ailleurs : un analyste atterrissant sur la vue CSIRT ne la voit pas
proposée une seconde fois, tandis qu'un auditeur, qui atterrit sur la vue
nationale, la garde.

Les capacités du menu sont celles que les vues ciblées contrôlent : un test
parcourt le menu de six rôles et suit chaque lien, de sorte que les deux ne
peuvent pas diverger sans que la suite échoue. Ajouter une entrée demande donc
de garder la vue correspondante — et l'inverse.

---

### Deux listes, pas une

L'administration présente les comptes en **deux listes distinctes**, parce
qu'il s'agit de deux populations sans cycle de vie commun :

| Liste | Qui | Ce qu'elle montre |
|-------|-----|-------------------|
| **Comptes métiers et administrateurs** | Les sept rôles hors signaleur, créés par un administrateur | Organisation de rattachement, état du second facteur, dernière connexion |
| **Comptes signaleurs** | Chercheurs et utilisateurs publics, inscrits librement | Identité publique, adresse vérifiée, réputation, rapports soumis |

L'action « Réinitialiser la double authentification » et le filtre
correspondant n'existent que sur la première : un compte signaleur n'y est
jamais soumis. La frontière est `BUSINESS_ROLES` dans
`apps/accounts/roles.py`, définie comme le complément des rôles signaleurs —
un rôle ajouté rejoint donc la population protégée par défaut, et il faut une
décision explicite pour l'en dispenser. C'est la même frontière que lit la
double authentification.

Le rôle se modifie **uniquement** depuis ces listes. Tout changement est
journalisé (`ROLE_CHANGED`) ; s'il fait passer le compte d'une population à
l'autre, un message le signale, faute de quoi le compte semblerait disparaître
de la liste.

> Attribuez `AUDITOR` pour toute mission d'inspection : le rôle voit tout et
> ne peut rien écrire.

---

## 2. Créer une organisation

**`/organizations/manage/new/`** ou `/admin/` → Organisations.

Champs importants : nom, sigle, type, secteur, domaine principal, email
officiel, responsable DSI, clé publique PGP, « accepte les signalements ».

Puis rattachez les utilisateurs (**Membres**) avec un rôle d'appartenance :
`MANAGER`, `DSI`, `SECURITY_CONTACT`, `ANALYST`, `OBSERVER`.

Les membres `MANAGER`, `DSI` et `SECURITY_CONTACT` sont **automatiquement
ajoutés comme participants** des dossiers concernant leur organisation.

---

## 3. Créer un programme

**Tableau de bord → Mes programmes → Créer un programme**

1. Renseigner le type (VDP ou Bug Bounty), l'organisation et la politique SLA.
2. Rédiger description, règles, Safe Harbor, politique de divulgation.
3. Déclarer le périmètre (cibles incluses et exclues).
4. Pour un Bug Bounty : renseigner la matrice de récompenses.
5. Passer le statut de `DRAFT` à `ACTIVE`.

Un programme `PUBLIC` et `ACTIVE` apparaît immédiatement sur `/programs/`.

---

## 4. Traiter un dossier

### File de traitement

- **`/cases/`** — liste filtrable, triée par score de priorité
- **`/cases/kanban/`** — vue Kanban en 7 colonnes

Le score de priorité (0–100) combine sévérité, secteur de l'organisation,
ancienneté et dépassements de SLA.

### Séquence type

1. **Accuser réception** — `RECEIVED` puis `ACKNOWLEDGED` (SLA 72 h).
2. **Assigner** un analyste.
3. **Qualifier** — sévérité, vecteur CVSS, CWE, organisation, étiquettes.
4. **Décider** — `VALIDATED`, `NEEDS_INFORMATION`, ou une issue de triage.
5. **Coordonner** — `VENDOR_CONTACTED`, échanges via la messagerie.
6. **Suivre la remédiation** — jusqu'à `FIX_VERIFIED`.
7. **Planifier la divulgation**, rédiger et publier l'advisory.
8. **Clore** le dossier.

### Messagerie

| Niveau | Usage |
|--------|-------|
| Participants | Échange avec le déclarant et l'organisation |
| Interne | Analyse entre équipes nationales |
| Restreint | Coordination nationale uniquement |

**Vérifiez le niveau avant d'envoyer.** Un message « Participants » est visible
du déclarant.

---

## 5. Publier un advisory

1. Depuis un dossier validé : **Rédiger un advisory** → brouillon assaini.
2. Compléter le **résumé public** (obligatoire), la description, l'impact et
   la solution.
3. Vérifier la chronologie publique et le crédit du chercheur.
4. `DRAFT` → `IN_REVIEW` → `APPROVED`.
5. Un coordinateur national publie.

### Contrôle avant publication

- [ ] Aucune preuve de concept, aucune étape de reproduction exploitable
- [ ] Aucune URL interne ni identifiant de dossier
- [ ] Correctif effectivement disponible
- [ ] Organisation affectée informée de la date
- [ ] Crédit conforme au choix du chercheur
- [ ] CVSS et CWE cohérents

Un advisory publié peut être **retiré** avec motif obligatoire ; l'opération
est journalisée.

---

## 6. Récompenses

1. Un analyste **propose** un montant (suggéré par la matrice du programme).
2. Des pairs peuvent **donner un avis**.
3. Un coordinateur national **approuve ou rejette**.
4. Le versement est **enregistré** après paiement effectif hors plateforme.

Un montant hors matrice est autorisé mais signalé et journalisé.

---

## 7. Politique de divulgation

**`/admin/` → Paramètres de site → `disclosure_policy`**

Le contenu est en Markdown et alimente `/disclosure-policy/`. La clé `about`
alimente `/about/`.

---

## 8. Politiques SLA

**`/admin/` → Politiques SLA**

| Paramètre | Défaut |
|-----------|--------|
| Accusé de réception | 72 heures |
| Premier triage | 5 jours |
| Réponse organisation | 7 jours |
| Remédiation Critical / High | 30 jours |
| Remédiation Medium | 60 jours |
| Remédiation Low | 90 jours |
| Divulgation | 90 jours |
| Seuil d'alerte | 80 % du délai |

Une politique peut être rattachée à un programme précis ; sinon la politique
par défaut s'applique.

---

## 9. Journal d'audit

**`/audit/`** — accessible à `SUPER_ADMIN`, `NATIONAL_COORDINATOR`, `AUDITOR`.

Filtres : action, acteur, objet. Les entrées sont **immuables**.

Points de vigilance :

- `PERMISSION_DENIED` répétés → tentative de contournement
- `LOGIN_FAILED` en série → attaque par force brute
- `ATTACHMENT_DOWNLOADED` massifs → exfiltration possible
- `ROLE_CHANGED` inattendu → compromission de compte administrateur

---

## 10. Exports

| Export | Chemin | Capacité |
|--------|--------|----------|
| Dossiers CSV | `/dashboard/exports/cases.csv` | `EXPORT_DATA` |
| Dossiers Excel | `/dashboard/exports/cases.xlsx` | `EXPORT_DATA` |
| Fiche PDF | `/dashboard/exports/case/EVDP-…​.pdf` | `EXPORT_DATA` |

Les exports respectent le périmètre de l'utilisateur et sont journalisés.
Le PDF porte la mention « Document interne — diffusion restreinte ».

---

## 11. Clés d'API

Création (aucune interface web au MVP) :

```bash
docker compose exec evdp-web python manage.py shell -c "
from apps.accounts.models import ApiKey, User
from apps.api.authentication import generate_key
raw, prefix, key_hash = generate_key()
ApiKey.objects.create(
    user=User.objects.get(email='analyste@csirt.bf'),
    label='Intégration SIEM', prefix=prefix, key_hash=key_hash)
print('Clé :', raw)
"
```

La valeur en clair n'est affichée qu'une fois. Révocation : décocher
« actif » dans `/admin/` → Clés d'API.

---

## 12. Tâches planifiées

| Tâche | Fréquence | Rôle |
|-------|-----------|------|
| `sweep_sla` | 30 min | Détecte échéances proches et dépassements |
| `sweep_disclosure_schedule` | Horaire | Alerte sur les divulgations à J-7 |
| `purge_expired_tokens` | 03:00 | Purge les jetons expirés |

Consultables et ajustables dans `/admin/` → Periodic tasks.

```bash
docker compose logs -f evdp-beat evdp-worker
docker compose exec evdp-web python manage.py shell -c \
  "from apps.coordination.tasks import sweep_sla; print(sweep_sla())"
```

---

## 13. Incidents courants

| Symptôme | Action |
|----------|--------|
| Dossier bloqué dans un état | Vérifier les transitions autorisées dans la fiche ; la machine à états peut exiger une étape intermédiaire |
| SLA non calculé | Vérifier qu'une politique SLA par défaut existe |
| Pièce jointe `PENDING` indéfiniment | ClamAV non configuré : le statut passe à `SKIPPED` après analyse |
| Emails non reçus | Vérifier `EMAIL_HOST` et les logs `evdp-web` |
| Advisory refusé à la publication | Le résumé public est obligatoire et le statut doit être `APPROVED` ou `SCHEDULED` |
| Chercheur ne voit pas son dossier | Vérifier qu'il en est bien le déclarant ou un participant |
