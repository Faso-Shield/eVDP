# Bug Bounty — eVDP

---

## 1. VDP et Bug Bounty : deux dispositifs distincts

| | **VDP** | **Bug Bounty** |
|---|---|---|
| Objectif | Faciliter la divulgation responsable | Inciter à la recherche sur un périmètre ciblé |
| Périmètre | Large, souvent l'ensemble du domaine public | Restreint et explicitement listé |
| Récompense | Aucune | Oui, selon une matrice |
| Éligibilité | Ouverte à tous, anonymat possible | Conditions explicites, compte vérifié |
| Signalement anonyme | Accepté | Refusé (paiement impossible) |
| Workflow | CVD classique | CVD + étapes sévérité et récompense |

Les deux dispositifs s'appuient sur le **même moteur de case management**.
Techniquement, ils partagent le modèle `Program`, discriminé par
`program_type` (voir ARCHITECTURE.md, DA-2).

---

## 2. Workflow Bug Bounty

```
SUBMITTED → TRIAGE → [NEEDS_INFORMATION] → VALIDATED
    → SEVERITY_ASSIGNED → BOUNTY_REVIEW → REWARD_APPROVED
    → REMEDIATION → FIX_AVAILABLE → VERIFICATION → FIX_VERIFIED
    → DISCLOSURE_SCHEDULED → PUBLISHED → CLOSED
```

Issues particulières : `DUPLICATE`, `OUT_OF_SCOPE`, `NOT_APPLICABLE`,
`INFORMATIVE`, `REJECTED`.

Les états `SEVERITY_ASSIGNED`, `BOUNTY_REVIEW` et `REWARD_APPROVED`
**n'existent pas** dans le workflow VDP : la machine à états les refuse.

---

## 3. Créer un programme

**Tableau de bord → Mes programmes → Créer un programme**

### Champs structurants

| Champ | Rôle |
|-------|------|
| Type | `BUG_BOUNTY` |
| Organisation | Entité responsable |
| Statut | `DRAFT` → `ACTIVE` → `PAUSED` / `CLOSED` |
| Confidentialité | `PUBLIC`, `RESTRICTED`, `PRIVATE` (sur invitation) |
| Dates | Début et fin de campagne |
| Délai de divulgation | 60 jours par défaut sur un Bug Bounty |
| Politique SLA | Échéances applicables |
| Email verifié requis | Recommandé : oui |
| Signalements anonymes | Recommandé : non |

### Contenus rédactionnels (Markdown)

Description, règles de test, hors périmètre, **Safe Harbor**, politique de
divulgation, conditions d'éligibilité.

---

## 4. Périmètre

Chaque cible est décrite indépendamment.

| Attribut | Valeurs |
|----------|---------|
| Portée | Dans le périmètre / Hors périmètre |
| Type | Domaine, URL, IP/CIDR, application mobile, API, code source, autre |
| Identifiant | `*.gouv.bf`, `api.exemple.bf`, `10.0.0.0/24`, … |
| Application / plateforme | Nom fonctionnel, iOS/Android/Web |
| Environnement | Production, préproduction, test |
| Priorité | P1 (critique) → P4 (faible) |
| Statut | Actif / inactif |

**Exemple**

*Dans le périmètre*
- `api.services.gov.bf` — API — P1 — Production
- `portail.services.gov.bf` — Domaine — P1 — Production
- Application mobile eServices — P2

*Hors périmètre*
- `test.services.gov.bf` — environnement de test
- Infrastructures tierces
- Déni de service, ingénierie sociale

---

## 4 bis. Conditions de participation

Un Bug Bounty ne peut récompenser qu'un chercheur **identifié et joignable de
façon sûre**. Deux conditions en découlent, appliquées à la soumission :

- **Compte obligatoire** — un Bug Bounty n'accepte jamais de signalement
  anonyme, contrairement à un VDP.
- **Adresse email vérifiée** — le compte doit avoir confirmé son adresse via
  le lien reçu à l'inscription.

Ces deux conditions sont **structurelles** pour un Bug Bounty : le modèle
refuse d'enregistrer un programme de ce type qui les désactiverait. Pour les
autres types de programme, `requires_verified_email` reste une politique
librement configurable, et le signalement anonyme demeure possible quand
`allows_anonymous_reports` est actif.

`Program.clean` ne garde toutefois que les enregistrements passés par un
formulaire : une ligne écrite en masse ou par migration peut porter
`allows_anonymous_reports=True` sur un Bug Bounty. La règle affichée et
celle appliquée se lisent donc toutes deux sur
`Program.accepts_anonymous_reports`, qui la dérive du type de programme,
et jamais sur le réglage brut.

Le refus est annoncé **à l'arrivée** — sur la fiche du programme comme sur le
formulaire de signalement atteint avec `?program=`, dont le bouton d'appel
renvoie alors vers la connexion. Un visiteur sans compte n'a ainsi pas à
rédiger un rapport pour se le voir refuser à l'envoi.

Ne pas confondre les deux réglages :

| Réglage | Porte sur |
|---------|-----------|
| `allows_anonymous_reports` | le droit de signaler **sans compte** |
| `requires_verified_email` | les déclarants **avec compte**, dont l'adresse doit être vérifiée |

### Délai de grâce et relance

Appliquer l'exigence prive du jour au lendemain les comptes déjà en base qui
n'ont jamais vérifié leur adresse. Un sursis leur est donc accordé, réglé par
trois variables d'environnement :

| Variable | Rôle |
|----------|------|
| `EVDP_VERIFICATION_ENFORCED_FROM` | date de bascule (AAAA-MM-JJ). Vide = application immédiate, sans sursis |
| `EVDP_VERIFICATION_GRACE_DAYS` | durée du sursis, 30 jours par défaut |
| `EVDP_VERIFICATION_REMINDER_DAYS` | jalons de relance, en jours restants (14, 7, 1) |

Le sursis vaut **uniquement pour les comptes créés avant la date de bascule**.
Un compte créé après doit vérifier son adresse immédiatement : lui accorder un
délai reviendrait à laisser une adresse non contrôlée participer à un Bug
Bounty, ce que la règle vise précisément à empêcher.

La tâche `apps.accounts.tasks.remind_unverified_accounts`, planifiée chaque
jour à 8 h 30, relance les comptes concernés à chaque jalon avec un lien de
vérification neuf. Un seul envoi par jour et par compte : la tâche peut être
rejouée sans risque.

Pendant le sursis, la page du programme et le formulaire de signalement
affichent la date limite plutôt qu'un refus.

### Rattrapage par le CSIRT

La relance par email rate par construction une partie de la cible : un compte
qui n'a jamais vérifié son adresse peut en avoir saisi une erronée ou morte.
Le tableau de bord CSIRT signale donc la cohorte concernée et propose son
export :

```
/dashboard/exports/comptes-non-verifies.csv
```

L'export liste les comptes à **J-1** de l'échéance, et les y maintient une
fois le sursis expiré — ce sont précisément ceux qu'il faut rattraper. Le
paramètre `?jours=N` élargit la fenêtre (maximum 90).

Colonnes : email, nom complet, rôle, date de création, dernière connexion,
date de la dernière relance, fin du sursis, nombre de signalements déposés.
Les deux dernières servent à prioriser : un compte qui a déjà contribué et
n'a jamais reçu de relance mérite un appel.

La liste contient des adresses email : l'export exige la capacité
`EXPORT_DATA` et est journalisé au même titre que les autres.

Le contrôle est fait dans `submit_report`, point d'entrée commun au formulaire
web, à l'API et à l'import CSAF. Un second contrôle à la proposition de
récompense couvre le cas d'un programme devenu exigeant après coup.

La page publique du programme annonce les conditions et, si le visiteur ne les
remplit pas, le lui dit avant qu'il ne rédige son rapport.

---

## 5. Matrice de récompenses

Configurée par programme, dans **Gérer le programme → Matrice de récompenses**.
Les montants sont **stockés en base** : aucun montant n'est codé en dur dans
l'application.

| Sévérité | Fourchette indicative (FCFA) |
|----------|------------------------------|
| CRITICAL | 750 000 – 2 000 000 |
| HIGH | 300 000 – 750 000 |
| MEDIUM | 100 000 – 300 000 |
| LOW | 0 – 100 000 |

La devise est configurable (`XOF` par défaut). Un budget total peut être
déclaré et son niveau de consommation est calculé à partir des récompenses
approuvées et payées.

### Montants variables par actif

Un palier peut viser un **actif précis du périmètre** au lieu du programme
entier. Une faille critique sur une API de production ne vaut pas la même
chose que sur un site vitrine, et c'est le principal levier pour orienter
l'effort des chercheurs vers ce qui compte.

La résolution est simple : le palier propre à l'actif s'applique s'il existe,
sinon celui du programme. On ne saisit donc une ligne par actif **que là où le
montant doit différer**, au lieu de dupliquer toute la grille pour chaque
cible.

L'actif concerné est retenu **au triage**, dans le champ *Actif du périmètre*
de la qualification. Sans actif retenu, la grille par défaut s'applique.

Deux garde-fous à la saisie : un palier ne peut pas viser le périmètre d'un
autre programme, ni une cible déclarée hors périmètre.

La page publique du programme affiche les montants propres à chaque actif en
regard de la cible concernée, et l'API les expose dans `reward_tiers` via le
champ `scope` (vide pour la grille par défaut).

---

## 6. Cycle de vie d'une récompense

```
PENDING → UNDER_REVIEW → APPROVED → PAID
   │            │
   └────────────┴──→ REJECTED / CANCELLED
```

### Séparation des responsabilités

| Action | Capacité | Rôles |
|--------|----------|-------|
| Proposer | `PROPOSE_BOUNTY` | Analyste CSIRT, DSI, responsable d'organisation, coordinateur |
| Donner un avis | `PROPOSE_BOUNTY` | Idem |
| **Approuver / rejeter** | `APPROVE_BOUNTY` | **Coordinateur national, administrateur** |
| Enregistrer un versement | `RECORD_PAYMENT` | Coordinateur national, administrateur |

Un analyste **ne peut pas** approuver la récompense qu'il a proposée : la
séparation est vérifiée côté serveur et testée.

### Montant hors matrice

Un montant sortant du palier de la sévérité reste possible — les situations
exceptionnelles existent — mais il est **explicitement journalisé** avec un
avertissement, et l'interface l'affiche en évidence.

---

## 7. Paiement

**Le MVP n'exécute aucun paiement réel.** `BountyPayment` enregistre une trace
comptable : montant, devise, moyen (virement bancaire, mobile money, autre),
référence externe, agent ayant enregistré, date.

Le versement effectif est réalisé hors plateforme par le service financier,
puis rapproché via la référence.

**Intégration future :** le champ `BountyPayment.method` et le statut
`SETTLED` constituent le point d'accroche d'un connecteur de paiement.

---

## 8. Espace chercheur

| Indicateur | Source |
|------------|--------|
| Rapports soumis | Nombre de dossiers créés |
| Rapports validés | Dossiers ayant atteint un état de validation |
| Rapports critiques | Dossiers validés de sévérité `CRITICAL` |
| Réputation | Somme des évènements de réputation |
| Taux de validation | Validés / soumis |
| Récompenses versées | Somme des récompenses `PAID` |
| Récompenses en cours | Récompenses non finalisées |

Le chercheur suit également ses messages, ses programmes et les advisories qui
le créditent.

### Ce que le bénéficiaire ne voit pas

La fiche d'une récompense se lit différemment selon le compte. Celui qui
l'instruit — capacité `PROPOSE_BOUNTY` ou `APPROVE_BOUNTY` — voit la
proposition, les avis de revue et la décision signée. Le chercheur qui la
reçoit voit ce qui le concerne : dossier, sévérité retenue, montant proposé,
montant approuvé, état d'avancement et versements enregistrés.

Lui restent invisibles le nom de qui a proposé, de qui a donné un avis et de
qui a signé, la justification interne, la note de décision et l'agent ayant
saisi le versement. Les avis ne sont pas seulement masqués par le gabarit :
ils ne sont pas chargés pour ce compte. Aucune commande — proposer, donner un
avis, approuver, enregistrer un versement — ne lui est offerte, et le serveur
refuse ces actions même en cas de requête forgée.

---

## 9. Bonnes pratiques

**Pour l'organisation**

1. Définir un périmètre restreint et sans ambiguïté.
2. Publier un Safe Harbor clair : c'est ce qui fait venir les chercheurs.
3. Calibrer les montants sur l'impact réel, pas sur la difficulté technique.
4. Répondre vite : la réactivité vaut autant que le montant.
5. Créditer systématiquement, sauf refus explicite du chercheur.

**Pour le chercheur**

1. Lire le périmètre et les règles **avant** de tester.
2. Un rapport = une vulnérabilité.
3. Arrêter l'exploitation dès la preuve établie ; ne jamais exfiltrer de données.
4. Fournir des étapes de reproduction complètes et une évaluation d'impact.
5. Respecter la confidentialité jusqu'à la divulgation coordonnée.
