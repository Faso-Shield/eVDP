# Processus de divulgation coordonnée (CVD) — eVDP · Workflow v2

Ce document décrit le cycle de vie d'un signalement, de sa soumission à la
clôture, conformément à **SPEC-eVDP-2026-V2** (workflow v2 et matrice RBAC,
23 septembre 2026). Il remplace les 24 statuts de la v1 par **11 étapes
principales**, une **branche Bug Bounty de 2 étapes** et **6 sorties
d'exception**.

---

## 1. Principes directeurs

1. **Un bouton, un rôle** — chaque étape a un seul propriétaire et un seul
   bouton pour avancer. Les autres rôles voient « En attente de : <rôle> ».
2. **Pré-requis bloquants** — le bouton reste grisé tant que les champs
   exigés manquent, avec la liste explicite (« Vecteur CVSS manquant »).
3. **Quatre yeux** — qualification, prime, rejet et publication sont validés
   par une personne différente de l'auteur. Le contrôle porte sur
   l'utilisateur, pas seulement sur le rôle.
4. **Exceptions à part** — compléments, rejet, doublon, renvoi et escalade
   sont des actions secondaires (menu « Autres actions »), jamais des boutons
   de validation, et exigent toutes un commentaire.
5. **Tout est audité** — chaque clic produit une entrée dans le journal
   append-only, refus compris.
6. **Preuves intouchables** — les pièces jointes du déclarant sont en lecture
   seule pour tous les rôles.

L'interface guide, le serveur décide : chaque règle affichée est vérifiée
par `apps.coordination.workflow.check_transition()`.

---

## 2. Chemin principal

| # | Statut de départ | Rôle | Bouton unique | Pré-requis bloquants | Statut d'arrivée | SLA |
|---|------------------|------|---------------|----------------------|------------------|-----|
| 0 | — | Déclarant | Soumettre le rapport | Formulaire complet, ≥ 1 pièce jointe (web et API) | `SUBMITTED` | — |
| 1 | `SUBMITTED` | Agent de triage | Accuser réception | Dossier ouvert au moins une fois | `ACKNOWLEDGED` | 72 h |
| 2 | `ACKNOWLEDGED` | Agent de triage | Déclarer recevable | Checklist : périmètre, organisation identifiée, PJ lisible | `IN_ANALYSIS` | 5 j avec l'étape 3 |
| 3 | `IN_ANALYSIS` | Analyste CSIRT | Soumettre la qualification | Vecteur CVSS v3.1 ou v4.0 saisi par un analyste, CWE, organisation confirmée | `VALIDATION_PENDING` | 5 j |
| 4 | `VALIDATION_PENDING` | Coordinateur ou analyste senior | Valider la qualification | Valideur ≠ auteur, commentaire | `VALIDATED` | 2 j |
| 5 | `VALIDATED` | Analyste CSIRT | Transmettre à l'organisation | Version « organisation » générée, identité protégée | `VENDOR_NOTIFIED` | — |
| 6 | `VENDOR_NOTIFIED` | Responsable DSI | Accepter et soumettre le plan de remédiation | Plan + date cible (30, 60 ou 90 j selon sévérité) | `REMEDIATION_IN_PROGRESS` | 5 j |
| 7 | `REMEDIATION_IN_PROGRESS` | Responsable DSI | Déclarer le correctif disponible | Description, version ou date de déploiement | `FIX_AVAILABLE` | 30 à 90 j |
| 8 | `FIX_AVAILABLE` | Analyste CSIRT | Confirmer le correctif | Compte rendu de contre-vérification | `FIX_VERIFIED` | 5 j |
| 9 | `FIX_VERIFIED` | Analyste CSIRT | Soumettre l'advisory | Brouillon assaini : aucun PoC, aucune IP, aucune URL | `ADVISORY_REVIEW` | — |
| 10 | `ADVISORY_REVIEW` | Coordinateur | Publier et clôturer | Relecture (≠ auteur), commentaire, prime réglée | `CLOSED` | — |

`RECEIVED` disparaît : l'accusé de réception suffit à marquer le dossier
comme reçu. Délai de remédiation par sévérité : Critique 30 j, Élevée 60 j,
Moyenne et Faible 90 j.

Les données exigées par une étape se saisissent dans la carte « Données de
l'étape » de la fiche du dossier (checklist de recevabilité, version
organisation, plan de remédiation, correctif, contre-vérification) ; la
qualification (CVSS, CWE, organisation) dans la carte « Qualification ».

---

## 3. Branche Bug Bounty et Wallet

La prime se décide dès la validation, **en parallèle** de la remédiation.
Le statut de prime (`Case.bounty_status`) est distinct du statut du dossier.

| # | Statut prime | Rôle | Bouton unique | Pré-requis | Arrivée |
|---|--------------|------|---------------|------------|---------|
| B1 | `BOUNTY_ELIGIBLE` | Analyste CSIRT | Proposer la prime | Montant de la matrice ; hors palier = justification écrite | `BOUNTY_PROPOSED` |
| B2 | `BOUNTY_PROPOSED` | Coordinateur | Approuver et créditer le Wallet | Approbateur ≠ proposeur, commentaire | `BOUNTY_CREDITED` |

- Un programme non éligible (VDP) passe directement en `NOT_ELIGIBLE` à
  l'étape 4. Le Coordinateur peut aussi déclarer un dossier non éligible.
- Le **Wallet** est un grand livre d'écritures (`WalletEntry` : crédit,
  ajustement, versement hors plateforme). Le solde est **calculé**, jamais
  stocké ni modifiable ; une écriture ne peut être ni modifiée ni supprimée.
- Aucun flux financier réel n'est déclenché (MVP).
- « Publier et clôturer » reste grisé tant que la prime n'est ni
  `BOUNTY_CREDITED` ni `NOT_ELIGIBLE`.

---

## 4. Sorties d'exception

| Action | Déclenchée par | Étapes | Effet | Retour |
|--------|----------------|--------|-------|--------|
| Demander des compléments | Triage, Analyste | 1 à 3 | `NEEDS_INFORMATION`, SLA suspendu | Déclarant : « Envoyer les compléments » → étape d'origine ; sans réponse sous 30 j → rejet proposé automatiquement |
| Proposer le rejet | Triage, Analyste | 1 à 3 | `REJECTION_PENDING` | Coordinateur : « Confirmer le rejet » → `REJECTED`, ou renvoi à l'étape d'origine |
| Marquer comme doublon | Triage, Analyste | 1 à 3 | `REJECTION_PENDING` (motif doublon) | Coordinateur confirme → `DUPLICATE`, rattaché à l'original sans fuite |
| Renvoyer à l'auteur | Coordinateur | 4, 10, B2 | Retour à l'étape précédente | — |
| Correctif insuffisant | Analyste | 8 | Retour en `REMEDIATION_IN_PROGRESS` | — |
| Escalader | Automatique (SLA dépassé) ou Coordinateur | 6, 7 | Alerte rouge, notification du Coordinateur | Le Coordinateur peut décider une divulgation à échéance après 90 j |

La DSI ne peut ni rejeter ni marquer un doublon : si elle conteste, elle
l'écrit dans le canal CSIRT ↔ organisation et le CSIRT décide.

---

## 5. Contrôles serveur (`check_transition`)

1. La transition existe dans `VDP_TRANSITIONS` pour le statut courant.
2. Le dossier est dans le périmètre de l'utilisateur (queryset filtré), sinon 404.
3. L'utilisateur possède la capacité requise par la transition.
4. Les pré-requis de l'étape sont remplis.
5. Quatre yeux : l'utilisateur n'est pas l'auteur de l'étape précédente
   (transitions marquées `four_eyes`) ; à l'étape 4, il n'est pas non plus
   l'auteur du vecteur CVSS.
6. Commentaire obligatoire le cas échéant.

Le refus est audité **hors transaction** ; l'application est atomique et
auditée. L'API expose le même moteur :
`GET /api/v1/reports/{case_id}/transition/` rend le bouton de l'utilisateur,
`POST` applique `{"action": "...", "comment": "..."}`.

---

## 6. SLA

| Échéance | Délai par défaut | Ouverte à | Soldée par |
|----------|------------------|-----------|------------|
| Accusé de réception | 72 h | Soumission | Étape 1 |
| Recevabilité et qualification | 5 jours | Soumission | Étape 3 (ou rejet / doublon) |
| Validation de la qualification | 2 jours | Étape 3 | Étape 4 ou renvoi |
| Plan de remédiation | 5 jours | Étape 5 | Étape 6 |
| Remédiation | Date cible du plan (≤ 30/60/90 j) | Étape 6 | Étape 7 |
| Contre-vérification | 5 jours | Étape 7 | Étape 8 ou « Correctif insuffisant » |
| Divulgation | Date planifiée | Planification | Publication |

`sweep_sla` (toutes les 30 min) passe une échéance en `APPROACHING` à 75 %
du délai et en `BREACHED` à échéance ; un dépassement **escalade
automatiquement** le dossier. `NEEDS_INFORMATION` suspend les échéances,
qui reprennent décalées de la durée de suspension. `sweep_information_requests`
(quotidien) propose le rejet des demandes restées sans réponse 30 jours.

Les cartes Kanban portent un badge vert, orange (75 %) ou rouge (échéance).

---

## 7. Matrice de visibilité

| Donnée | Déclarant | Triage | Analyste | Coordinateur | DSI / Resp. org | Auditeur | Super admin |
|--------|-----------|--------|----------|--------------|-----------------|----------|-------------|
| Rapport et pièces jointes | Lecture (les siens) | Lecture | Lecture | Lecture | Version organisation, à partir de l'étape 5 | Métadonnées | — |
| Identité du chercheur | Complet (la sienne) | Lecture | Lecture | Lecture | Pseudonyme ou rien selon le mode | Pseudonymisée | — |
| Score et vecteur CVSS | — | Lecture | Complet | Lecture | Score final | Lecture | — |
| Notes de triage et d'analyse (canal interne) | — | Complet | Complet | Lecture | — | — | — |
| Canal chercheur | Complet | Complet | Complet | Complet | — | — | — |
| Canal CSIRT ↔ organisation | — | Complet | Complet | Complet | Complet | — | — |
| Wallet | Lecture (le sien) | — | — | Complet | — | — | — |
| Brouillon d'advisory | — | — | Complet | Lecture (relecture) | Lecture | Lecture | — |
| Journal d'audit | — | — | — | Lecture | — | Complet (+ exports) | Logs techniques |

Le déclarant voit un **statut simplifié à 5 paliers** (Reçu, En analyse,
Validé, En correction, Publié) et seulement les jalons publics de la
chronologie. Un accès hors périmètre renvoie **404, jamais 403**.

---

## 8. Rôles

| Rôle spec v2 | Rôle(s) dans le code | Boutons de workflow | Actions secondaires |
|--------------|----------------------|---------------------|---------------------|
| CHERCHEUR_VDP | `SECURITY_RESEARCHER`, `BUG_BOUNTY_RESEARCHER`, `PUBLIC_USER` | Soumettre le rapport | Envoyer les compléments |
| TRIAGER | `TRIAGER` | Accuser réception, Déclarer recevable | Compléments, rejet, doublon |
| CSIRT_ANALYST | `CSIRT_ANALYST` | Soumettre la qualification, Transmettre à l'organisation, Confirmer le correctif, Soumettre l'advisory, Proposer la prime | Compléments, rejet, doublon, correctif insuffisant |
| NAT_COORDINATOR | `NATIONAL_COORDINATOR` (+ analyste senior, permission individuelle `is_senior_analyst`, pour l'étape 4) | Valider la qualification, Approuver et créditer le Wallet, Publier et clôturer | Confirmer rejet ou doublon, renvoyer, escalader |
| VENDOR_ADMIN | `DSI_ADMIN`, `ORGANIZATION_MANAGER` | Plan de remédiation, Correctif disponible | — |
| (hors spec) | `AUDITOR` | Aucun | — |
| (hors spec) | `SUPER_ADMIN` | Aucun : administration technique seulement (comptes, rôles, configuration, SLA, matrices de prime), **aucun accès au contenu des dossiers** (ISO/IEC 27001 A.5.3) | — |

---

## 9. Réputation

| Évènement | Points (configurable) |
|-----------|----------------------|
| Rapport validé | +10 |
| Sévérité High | +25 |
| Sévérité Critical | +50 |
| Doublon | 0 |
| Rapport abusif | −20 |

Barème pilotable par les variables `EVDP_REP_*`. L'attribution est
idempotente par dossier et **jamais modifiable par le chercheur**.

---

## 10. Migration depuis la v1

La migration `coordination.0008_workflow_v2_data` convertit les 24 statuts
v1 (dossiers et historique) :

| v1 | v2 |
|----|----|
| `DRAFT`, `SUBMITTED`, `RECEIVED` | `SUBMITTED` |
| `ACKNOWLEDGED` | `ACKNOWLEDGED` |
| `TRIAGE` | `IN_ANALYSIS` |
| `NEEDS_INFORMATION` | `NEEDS_INFORMATION` (origine `IN_ANALYSIS`) |
| `VALIDATED`, `SEVERITY_ASSIGNED`, `BOUNTY_REVIEW`, `REWARD_APPROVED`, `IN_PROGRESS` | `VALIDATED` |
| `VENDOR_CONTACTED`, `VENDOR_ACKNOWLEDGED` | `VENDOR_NOTIFIED` |
| `REMEDIATION` | `REMEDIATION_IN_PROGRESS` |
| `FIX_AVAILABLE`, `VERIFICATION` | `FIX_AVAILABLE` |
| `FIX_VERIFIED`, `DISCLOSURE_SCHEDULED` | `FIX_VERIFIED` |
| `PUBLISHED`, `CLOSED` | `CLOSED` |
| `REJECTED`, `OUT_OF_SCOPE`, `NOT_APPLICABLE`, `INFORMATIVE` | `REJECTED` |
| `DUPLICATE` | `DUPLICATE` |

La branche prime est initialisée depuis les récompenses existantes, et
`bounty.0006_wallet_backfill` alimente le grand livre (crédits et
versements déjà enregistrés). Les dossiers en `IN_ANALYSIS` migrés doivent
être requalifiés par un analyste (l'auteur du CVSS n'était pas tracé en v1).

Diagrammes : `docs/diagrams/cvd-workflow.md`.
