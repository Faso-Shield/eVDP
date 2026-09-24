# Processus de divulgation coordonnée (CVD) — eVDP · Workflow v2

Ce document décrit le cycle de vie d'un signalement, de sa soumission à la
clôture, tel qu'implémenté d'après le document **« Workflow v2 & Matrice
RBAC »** (aligné sur SPEC-eVDP-2026-V2, 23 septembre 2026). Il remplace les
24 statuts historiques par **11 étapes principales**, une **branche Bug Bounty
de 2 étapes** et **6 sorties d'exception**.

Code de référence : `apps/coordination/workflow.py` (table des actions et
`check_transition()`), `apps/coordination/services.py` (`perform_action()`),
`apps/coordination/visibility.py` (matrice de visibilité),
`apps/accounts/roles.py` (capacités). Diagrammes :
[`docs/diagrams/cvd-workflow.md`](diagrams/cvd-workflow.md),
[`docs/diagrams/bug-bounty-workflow.md`](diagrams/bug-bounty-workflow.md),
[`docs/diagrams/rbac.md`](diagrams/rbac.md).

---

## 1. Principes directeurs

1. **Un bouton, un rôle** — chaque étape n'a qu'un bouton principal, affiché
   au seul rôle propriétaire ; les autres lisent « En attente de : &lt;rôle&gt; ».
2. **Pré-requis bloquants** — le bouton reste grisé tant qu'un champ exigé
   manque, avec la liste de ce qui manque (« Vecteur CVSS manquant »).
3. **Quatre yeux** — qualification, prime, rejet et publication sont validés
   par une personne différente de l'auteur de l'étape précédente. Le contrôle
   porte sur **l'utilisateur**, pas seulement sur le rôle.
4. **Exceptions à part** — compléments, rejet, doublon, renvoi et escalade sont
   des actions secondaires (menu « Autres actions »), jamais des boutons de
   validation. Toutes exigent un commentaire.
5. **Tout est audité** — chaque clic produit une entrée dans le journal
   append-only, refus compris (le refus est journalisé hors transaction).
6. **Preuves intouchables** — les pièces jointes du déclarant sont en lecture
   seule pour tous les rôles (aucune vue ni admin ne les modifie).
7. **Contenu au seul responsable de l'étape** — seul le compte responsable de
   l'étape en cours (propriétaire du bouton attendu, dossier ou branche prime ;
   celui qui l'a pris en charge s'il y en a un) accède au contenu du dossier : rapport, pièces
   jointes, messagerie, remédiation, export PDF. Les autres comptes qui voient
   le dossier n'en lisent que les métadonnées (titre, statut, « En attente
   de », échéances). Le déclarant garde toujours l'accès à son propre rapport.
   Un dossier clos n'a plus de responsable : son contenu n'est plus lu par
   personne côté métier. La règle vaut aussi pour l'accès au dossier lui-même,
   pour tous les comptes métiers (agent de triage, analyste, Coordinateur,
   DSI, responsable d'organisation) : chacun ne voit un dossier (liste,
   Kanban, fiche, API) et n'agit dessus que lorsqu'il est responsable de son
   étape en cours ; une fois son étape franchie, le dossier sort de son
   périmètre (404). Le Coordinateur voit ainsi les étapes 4 et 10, les rejets
   à confirmer, les primes à approuver (B2) et les dossiers escaladés ; la DSI
   les étapes 6 et 7. L'auditeur, sans étape, garde une vue nationale en
   métadonnées ; le super admin ne voit aucun dossier.

   Conséquences : l'escalade est automatique (SLA des étapes 6 ou 7 dépassé)
   et fait du Coordinateur le responsable du dossier jusqu'à sa décision de
   divulgation à échéance. La fiche d'une prime reste accessible à qui
   enregistre les versements (`RECORD_PAYMENT`) tant qu'un versement est à
   enregistrer ou à confirmer, et une fois réglé pour sa preuve. Les actions d'exception des étapes 1 à 3 et
   « Correctif insuffisant » sont réservées à ce responsable.
8. **Prise en charge** — plusieurs comptes d'un même rôle peuvent être
   responsables d'une étape (par exemple plusieurs analystes). L'un d'eux
   clique « Prendre en charge » : le dossier sort de la file de ses collègues
   du même rôle, qui ne reçoivent plus ses avis. Il peut ensuite le
   « Transférer à un collègue » du même rôle (absence, relais). La prise en
   charge suit le dossier sur les étapes de ce rôle (l'analyste le garde de
   l'étape 3 à l'étape 9) et ne gêne jamais les autres rôles. Elle est
   journalisée. Il n'existe plus d'assignation manuelle par un tiers.
9. **Un avis par étape** — à chaque étape franchie (et dès la soumission), le
   responsable de l'étape suivante reçoit une notification et un email
   (« Action attendue »), sauf s'il est l'auteur de l'action.
10. **Déclarant anonyme** — un déclarant sans compte ou ayant choisi
   l'anonymat n'a aucun canal de réponse : « Demander des compléments »
   n'est pas proposé (et refusé par le serveur), et le canal chercheur est
   fermé en écriture aux comptes métiers.

---

## 2. Chemin principal

```
SUBMITTED → ACKNOWLEDGED → IN_ANALYSIS → VALIDATION_PENDING → VALIDATED
  → VENDOR_NOTIFIED → REMEDIATION_IN_PROGRESS → FIX_AVAILABLE
  → FIX_VERIFIED → ADVISORY_REVIEW → CLOSED
```

| # | Départ | Rôle | Bouton (clé d'action) | Pré-requis bloquants | Arrivée | SLA |
|---|--------|------|-----------------------|----------------------|---------|-----|
| 0 | — | Déclarant | Soumettre le rapport | Formulaire complet, **≥ 1 pièce jointe** (vérifié côté serveur, web et API) | `SUBMITTED` | — |
| 1 | `SUBMITTED` | Agent de triage | Accuser réception (`acknowledge`) | Dossier ouvert au moins une fois | `ACKNOWLEDGED` | 72 h |
| 2 | `ACKNOWLEDGED` | Agent de triage | Déclarer recevable (`declare_admissible`) | Checklist : périmètre, organisation identifiée, PJ lisible | `IN_ANALYSIS` | 5 j avec l'étape 3 |
| 3 | `IN_ANALYSIS` | Analyste CSIRT | Soumettre la qualification (`submit_qualification`) | Vecteur CVSS v3.1 ou v4.0, CWE, organisation confirmée | `VALIDATION_PENDING` | 5 j |
| 4 | `VALIDATION_PENDING` | Coordinateur ou analyste senior | Valider la qualification (`validate_qualification`) | Valideur ≠ auteur, commentaire | `VALIDATED` | 2 j |
| 5 | `VALIDATED` | Analyste CSIRT | Transmettre à l'organisation (`notify_vendor`) | Organisation renseignée ; identité protégée selon le mode | `VENDOR_NOTIFIED` | — |
| 6 | `VENDOR_NOTIFIED` | Responsable DSI | Accepter et soumettre le plan de remédiation (`submit_remediation_plan`) | Plan + date cible ≤ 30/60/90 j selon sévérité | `REMEDIATION_IN_PROGRESS` | 5 j |
| 7 | `REMEDIATION_IN_PROGRESS` | Responsable DSI | Déclarer le correctif disponible (`declare_fix`) | Description + version ou date de déploiement | `FIX_AVAILABLE` | date cible |
| 8 | `FIX_AVAILABLE` | Analyste CSIRT | Confirmer le correctif (`confirm_fix`) | Compte rendu de contre-vérification | `FIX_VERIFIED` | 5 j |
| 9 | `FIX_VERIFIED` | Analyste CSIRT | Soumettre l'advisory (`submit_advisory`) | Brouillon assaini : aucun PoC, aucune IP, aucune URL sensible | `ADVISORY_REVIEW` | — |
| 10 | `ADVISORY_REVIEW` | Coordinateur | Publier et clôturer (`publish_and_close`) | Relecture faite, crédit conforme au choix du chercheur, branche prime terminée, publieur ≠ auteur, commentaire | `CLOSED` | — |

**Rédaction de l'advisory (étapes 9 et 10).** Le bouton « Rédiger un
advisory » de la fiche du dossier n'apparaît qu'au responsable de l'étape :
l'analyste à l'étape 9, le Coordinateur à l'étape 10 (« Relire et modifier
l'advisory »). Le premier clic génère une proposition complète à partir du
dossier (qualification, CWE et CVSS, produit, versions affectée et corrigée,
correctif déclaré et vérifié, crédit du chercheur, chronologie publique) ; le
texte libre du déclarant n'y est repris qu'assaini (sans code, URL, adresse IP
ni preuve de concept). Un second clic rouvre le même brouillon. Le
Coordinateur peut ensuite le modifier, le valider (« Publier et clôturer »)
ou clôturer le dossier sans publication.

Délai de remédiation par sévérité : **Critique 30 j, Élevée 60 j, Moyenne et
Faible 90 j**. `RECEIVED` disparaît : l'assignation automatique suffit à
marquer le dossier comme reçu.

---

## 3. Branche Bug Bounty et Wallet

La prime se décide dès la validation, en parallèle de la remédiation. Le
statut de prime (`Case.bounty_stage`) est **distinct** du statut du dossier.

| # | Statut prime | Rôle | Bouton | Pré-requis | Arrivée |
|---|--------------|------|--------|------------|---------|
| B1 | `BOUNTY_ELIGIBLE` | Analyste CSIRT | Proposer la prime (`propose_bounty`) | Montant issu de la matrice ; hors palier = justification écrite | `BOUNTY_PROPOSED` |
| B2 | `BOUNTY_PROPOSED` | Coordinateur | Approuver et créditer le Wallet (`approve_bounty`) | Approbateur ≠ proposeur, commentaire | `BOUNTY_CREDITED` |

- Un programme non éligible (VDP, déclarant non identifié) passe directement en
  `NOT_ELIGIBLE` à l'étape 4. Une prime refusée ramène aussi à `NOT_ELIGIBLE`.
- Le **Wallet** est un grand livre d'écritures (`bounty.WalletEntry` : crédit,
  ajustement, versement hors plateforme). Le solde est **calculé**
  (`bounty.services.wallet_balance`), jamais stocké ni modifiable ; une écriture
  ne se modifie ni ne se supprime.
- Aucun flux financier réel n'est déclenché : le versement effectif reste hors
  plateforme (MVP). Le Coordinateur (`RECORD_PAYMENT`) enregistre le versement
  puis en confirme le règlement, preuve à l'appui, une fois le correctif
  vérifié ; le Wallet n'est débité qu'à cette confirmation. La référence de
  paiement en clair (nom légal, moyen principal) lui est affichée sur la fiche
  de la prime, consultation journalisée — jamais au super admin.
- « Publier et clôturer » reste grisé tant que la prime n'est pas en
  `BOUNTY_CREDITED` ou `NOT_ELIGIBLE`.

---

## 4. Sorties d'exception

| Action (clé) | Déclenchée par | Étapes | Effet | Retour |
|--------------|----------------|--------|-------|--------|
| Demander des compléments (`request_information`) | Triage, Analyste | 1 à 3 | `NEEDS_INFORMATION`, SLA suspendu | Déclarant : « Envoyer les compléments » (`send_information`) → étape d'origine, SLA reporté ; sans réponse sous 30 j → rejet proposé automatiquement (`tasks.sweep_needs_information`) |
| Proposer le rejet (`propose_rejection`) | Triage, Analyste | 1 à 3 | `REJECTION_PENDING` | Coordinateur : « Confirmer le rejet » (`confirm_rejection`) → `REJECTED`, ou renvoi (`return_rejection`) à l'étape d'origine |
| Marquer comme doublon (`propose_duplicate`) | Triage, Analyste | 1 à 3 | `REJECTION_PENDING` (motif doublon) | Coordinateur confirme → `DUPLICATE`, rattaché à l'original sans fuite |
| Renvoyer à l'auteur (`return_to_author`, `return_bounty`) | Coordinateur | 4, 10, B2 | Retour à l'étape précédente | — |
| Correctif insuffisant (`insufficient_fix`) | Analyste | 8 | Retour en `REMEDIATION_IN_PROGRESS` | — |
| Proposer une clôture sans advisory (`propose_closure`) | Analyste | 9 | `ADVISORY_REVIEW` sans brouillon | Le Coordinateur décide : rédiger et publier, ou clôturer sans publication |
| Clôturer sans publication (`close_without_advisory`) | Coordinateur | 10 | `CLOSED` sans advisory publié (branche prime terminée, commentaire, quatre yeux) | Le déclarant voit « Clôturé », jamais « Publié » |
| Escalader | Automatique (SLA 6 ou 7 dépassé) | 6, 7 | Alerte rouge ; le Coordinateur devient responsable du dossier | Le Coordinateur peut décider une divulgation à échéance (`decide_deadline_disclosure`) après 90 j : l'advisory peut alors être soumis sans correctif |

La DSI ne peut ni rejeter ni marquer un doublon : si elle conteste, elle
l'écrit dans le canal CSIRT ↔ organisation et le CSIRT décide.

---

## 5. Contrôles serveur (`check_transition`)

L'interface guide, le serveur décide. Pour chaque action :

1. la transition existe pour le statut courant (`VDP_TRANSITIONS`) ;
2. l'utilisateur possède la capacité requise ;
3. le dossier est dans son périmètre (sinon **404**, jamais 403) ;
4. les pré-requis de l'étape sont remplis (la réponse liste ce qui manque) ;
5. règle des quatre yeux : l'utilisateur n'est pas l'auteur de l'étape
   précédente pour les actions concernées ;
6. le refus est audité hors transaction ; l'application est atomique et auditée.

Points d'entrée : bouton web `POST /cases/<id>/actions/<clé>/`, API
`POST /api/v1/reports/<id>/actions/` (`{"action": "<clé>", "comment": "…"}`),
et `/transition/` conservé pour compatibilité.

---

## 6. Interface

- Un seul bouton principal par dossier, visible du seul propriétaire de
  l'étape ; les autres voient « En attente de : &lt;rôle&gt; ».
- Bouton grisé tant qu'un pré-requis manque, avec la liste explicite.
- Clic = fenêtre de confirmation (`<dialog>`) ; commentaire obligatoire aux
  étapes 4, 10 et B2 et pour toute action d'exception.
- Actions d'exception dans un menu secondaire.
- Badge d'échéance sur chaque carte Kanban : vert, **orange à 75 %** du SLA,
  rouge à échéance ; mention « Escaladé ».
- Le déclarant voit un statut simplifié à 5 paliers (Reçu, En analyse,
  Validé, En correction, Publié — ou « Clôturé sans suite »).

---

## 7. Matrice de visibilité

Légende : Complet = lecture et écriture · Lecture = lecture seule ·
Partiel = voir la note · — = aucun accès.

| Donnée | Déclarant | Triage | Analyste | Coordinateur | DSI / Resp. org | Auditeur | Super admin |
|--------|-----------|--------|----------|--------------|-----------------|----------|-------------|
| Rapport et pièces jointes | Lecture (les siens) | Lecture | Lecture | Lecture | À partir de l'étape 5, son organisation | Métadonnées | — |
| Identité du chercheur | Complet (la sienne) | Lecture | Lecture | Lecture | Pseudonyme ou rien selon le mode | Pseudonymisée | Compte seulement |
| Score et vecteur CVSS | — | Lecture | Complet | Lecture | Score final | Lecture | — |
| Notes de triage et d'analyse (canal `INTERNAL`) | — | Complet | Complet | Lecture | — | Lecture | — |
| Canal chercheur (`RESEARCHER`) | Complet | Complet | Complet | Complet | — | Lecture | — |
| Canal CSIRT ↔ organisation (`ORGANIZATION`) | — | — | Complet | Complet | Complet | Lecture | — |
| Wallet | Lecture (le sien) | — | Montant proposé | Complet | — | Lecture | — |
| Brouillon d'advisory | — | — | Complet | Complet | Lecture | Lecture | — |
| Journal d'audit | — | — | — | Lecture | — | Complet | Logs techniques |

Le super admin perd l'accès au contenu des dossiers, y compris dans
l'administration Django (`core.admin.CaseContentAdminMixin`) : l'administration
technique est séparée du métier (ISO/IEC 27001 A.5.3).

---

## 8. Rôles

| Rôle spec v2 | Rôle(s) dans le code | Boutons de workflow | Actions secondaires |
|--------------|----------------------|---------------------|---------------------|
| CHERCHEUR_VDP | `SECURITY_RESEARCHER`, `BUG_BOUNTY_RESEARCHER`, `PUBLIC_USER` | Soumettre le rapport | Envoyer les compléments |
| TRIAGER | `TRIAGER` | Accuser réception, Déclarer recevable | Compléments, rejet, doublon |
| CSIRT_ANALYST | `CSIRT_ANALYST` | Soumettre la qualification, Transmettre, Confirmer le correctif, Soumettre l'advisory, Proposer la prime | Compléments, rejet, doublon, correctif insuffisant |
| NAT_COORDINATOR | `NATIONAL_COORDINATOR` (+ analyste senior : `User.is_senior_analyst` → `VALIDATE_SEVERITY`) | Valider la qualification, Approuver et créditer, Publier et clôturer | Confirmer rejet/doublon, renvoyer, escalader, divulgation à échéance |
| VENDOR_ADMIN | `DSI_ADMIN` (et `ORGANIZATION_MANAGER`, mêmes boutons) | Plan de remédiation, Correctif disponible | — |
| (hors spec) | `AUDITOR` | Aucun | — |
| (hors spec) | `SUPER_ADMIN` | Aucun | — |

---

## 9. SLA

| Échéance (`SLAKind`) | Délai par défaut | Ouverte à | Soldée à |
|----------------------|------------------|-----------|----------|
| `ACKNOWLEDGEMENT` | 72 h | Soumission | Étape 1 |
| `TRIAGE` | 5 j | `ACKNOWLEDGED` | Étape 3 (soumission de la qualification) |
| `VALIDATION` | 2 j | `VALIDATION_PENDING` | Étape 4 |
| `VENDOR_RESPONSE` | 5 j | `VENDOR_NOTIFIED` | Étape 6 |
| `REMEDIATION` | Date cible du plan | `REMEDIATION_IN_PROGRESS` | Étape 7 |
| `VERIFICATION` | 5 j | `FIX_AVAILABLE` | Étape 8 |

`apps.coordination.tasks.sweep_sla` (toutes les 30 min) passe une échéance en
`APPROACHING` à **75 %** du délai puis en `BREACHED` à l'échéance ; un
dépassement de `VENDOR_RESPONSE` ou `REMEDIATION` escalade le dossier. Une
demande de compléments suspend les SLA en cours ; ils sont reportés de la durée
de la suspension au retour.

---

## 10. Migration des 24 statuts historiques

Migration de données `coordination.0008_workflow_v2_donnees` (**mapping à
valider par la coordination**) :

| Anciens statuts | Nouveau statut |
|-----------------|----------------|
| `DRAFT`, `SUBMITTED`, `RECEIVED` | `SUBMITTED` |
| `ACKNOWLEDGED`, `TRIAGE` | `ACKNOWLEDGED` (recevabilité à reconfirmer) |
| `NEEDS_INFORMATION` | `NEEDS_INFORMATION` (origine : `ACKNOWLEDGED`) |
| `VALIDATED`, `SEVERITY_ASSIGNED`, `BOUNTY_REVIEW`, `REWARD_APPROVED`, `IN_PROGRESS` | `VALIDATED` |
| `VENDOR_CONTACTED` | `VENDOR_NOTIFIED` |
| `VENDOR_ACKNOWLEDGED`, `REMEDIATION` | `REMEDIATION_IN_PROGRESS` |
| `FIX_AVAILABLE`, `VERIFICATION` | `FIX_AVAILABLE` |
| `FIX_VERIFIED`, `DISCLOSURE_SCHEDULED` | `FIX_VERIFIED` |
| `PUBLISHED`, `CLOSED` | `CLOSED` |
| `REJECTED`, `OUT_OF_SCOPE`, `NOT_APPLICABLE`, `INFORMATIVE` | `REJECTED` |
| `DUPLICATE` | `DUPLICATE` |

La même migration range les messages dans les nouveaux canaux (ancien fil
« participants » → canal chercheur, ou canal organisation si l'auteur est un
compte d'organisation ; « restreint » → notes internes), calcule le statut de
prime, reprend dans le Wallet les primes déjà approuvées ou versées, et aligne
la politique SLA par défaut (délais v2, seuil 75 %). L'historique des statuts
n'est pas réécrit : c'est une trace d'audit.
