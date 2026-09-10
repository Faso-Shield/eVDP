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
