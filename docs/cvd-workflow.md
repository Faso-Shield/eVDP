# Processus de divulgation coordonnée (CVD) — eVDP

Ce document décrit le cycle de vie complet d'un signalement, de sa réception
à la publication de l'advisory.

---

## 1. Principes

1. **Privé par défaut** — un rapport n'est jamais publié automatiquement.
2. **Coordination avant publication** — l'organisation affectée est toujours contactée.
3. **Délai raisonnable** — divulgation coordonnée à 90 jours par défaut.
4. **Crédit au chercheur** — selon son choix d'identité.
5. **Tout est tracé** — chaque décision figure dans le journal d'audit.

---

## 2. États du workflow

| État | Signification |
|------|---------------|
| `DRAFT` | Brouillon non soumis |
| `SUBMITTED` | Rapport soumis, en attente de prise en charge |
| `RECEIVED` | Réception enregistrée par l'équipe |
| `ACKNOWLEDGED` | Accusé de réception envoyé au déclarant |
| `TRIAGE` | Qualification technique en cours |
| `NEEDS_INFORMATION` | Informations complémentaires demandées |
| `VALIDATED` | Vulnérabilité confirmée |
| `DUPLICATE` | Doublon d'un dossier existant |
| `REJECTED` | Non retenue |
| `OUT_OF_SCOPE` | Hors périmètre du programme |
| `NOT_APPLICABLE` | Sans objet |
| `INFORMATIVE` | Information utile sans vulnérabilité exploitable |
| `IN_PROGRESS` | Prise en charge engagée |
| `VENDOR_CONTACTED` | Organisation affectée contactée |
| `VENDOR_ACKNOWLEDGED` | Organisation a accusé réception |
| `REMEDIATION` | Correction en cours |
| `FIX_AVAILABLE` | Correctif disponible |
| `VERIFICATION` | Vérification du correctif |
| `FIX_VERIFIED` | Correctif vérifié |
| `DISCLOSURE_SCHEDULED` | Date de divulgation fixée |
| `PUBLISHED` | Advisory publié |
| `CLOSED` | Dossier clos |

### Parcours nominal

```
SUBMITTED → TRIAGE → VALIDATED → VENDOR_CONTACTED → REMEDIATION
    → FIX_AVAILABLE → VERIFICATION → FIX_VERIFIED
    → DISCLOSURE_SCHEDULED → PUBLISHED → CLOSED
```

Toute transition non déclarée dans `apps/coordination/workflow.py` est
**interdite** et retourne une erreur explicite. Voir le diagramme
`docs/diagrams/cvd-workflow.md`.

---

## 3. Étapes détaillées

### 3.1 Réception

Le signalement arrive par le formulaire public, l'API ou un import CSAF.
`reports.services.submit_report()` crée le rapport, ouvre le Case
`EVDP-AAAA-NNNNNN`, initialise la chronologie, rattache les participants,
planifie les SLA, journalise et notifie.

Le déclarant reçoit immédiatement une référence de suivi.

### 3.2 Accusé de réception — SLA 72 h

Un analyste passe le dossier en `RECEIVED` puis `ACKNOWLEDGED`. L'échéance
`ACKNOWLEDGEMENT` est automatiquement soldée.

### 3.3 Triage — SLA 5 jours

L'analyste qualifie :

- sévérité retenue (éventuellement calculée depuis un vecteur CVSS v3.1) ;
- CWE ;
- organisation affectée ;
- étiquettes.

Issues possibles : `VALIDATED`, `NEEDS_INFORMATION`, `DUPLICATE`, `REJECTED`,
`OUT_OF_SCOPE`, `NOT_APPLICABLE`, `INFORMATIVE`.

Capacité requise : `TRIAGE_CASE`.

### 3.4 Validation

À la validation :

- l'horodatage `validated_at` est posé ;
- la date de divulgation est calculée (délai du programme) ;
- l'échéance de remédiation est ouverte selon la sévérité ;
- le chercheur reçoit ses points de réputation.

### 3.5 Coordination — SLA 7 jours

L'organisation affectée est contactée (`VENDOR_CONTACTED`). Les échanges
passent par la messagerie du dossier. Les analystes disposent d'un niveau
`INTERNAL` invisible du déclarant et de l'organisation.

### 3.6 Remédiation

SLA selon la sévérité : 30 jours (Critical/High), 60 (Medium), 90 (Low).
Le correctif est déclaré (`FIX_AVAILABLE`) puis vérifié (`VERIFICATION` →
`FIX_VERIFIED`), idéalement avec le chercheur.

### 3.7 Divulgation

Une date est fixée (`DISCLOSURE_SCHEDULED`). Un analyste rédige l'advisory à
partir du dossier — **sans preuve de concept ni étape de reproduction**. Après
relecture et approbation, un coordinateur national publie.

Capacité requise pour publier : `PUBLISHED` → `PUBLISH_ADVISORY`.

### 3.8 Clôture

Le dossier passe en `CLOSED`. Les échéances restantes sont annulées.

---

## 4. SLA

| Échéance | Délai par défaut | Ouverte à | Soldée par |
|----------|------------------|-----------|------------|
| Accusé de réception | 72 h | Soumission | `RECEIVED` / `ACKNOWLEDGED` |
| Premier triage | 5 jours | Soumission | `TRIAGE` ou issue de triage |
| Réponse organisation | 7 jours | `VENDOR_CONTACTED` | `VENDOR_ACKNOWLEDGED` |
| Remédiation | 30 / 60 / 90 j | `VALIDATED` ou `REMEDIATION` | `FIX_AVAILABLE` / `FIX_VERIFIED` |
| Divulgation | Date planifiée | Planification | Publication |

`apps.coordination.tasks.sweep_sla` s'exécute toutes les 30 minutes :
il marque `APPROACHING` à 80 % du délai, puis `BREACHED` au dépassement, et
notifie les participants. Un dépassement augmente le score de priorité du
dossier.

Les délais sont modifiables via **Administration → Politiques SLA**.

---

## 5. Doublons

Un analyste rattache le dossier à l'original :

```python
mark_duplicate(case, original, actor, comment="Même vulnérabilité")
```

Le déclarant voit uniquement : « Votre rapport a été identifié comme
doublon. » L'identifiant et le contenu du dossier original ne lui sont
**jamais** révélés — seule la coordination nationale voit le lien.

---

## 6. Réputation

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

## 7. Rôles impliqués

| Étape | Rôles habilités |
|-------|-----------------|
| Soumission | Chercheur, citoyen, professionnel (compte optionnel) |
| Accusé de réception, triage | `TRIAGER`, `CSIRT_ANALYST`, `NATIONAL_COORDINATOR` |
| Coordination | `CSIRT_ANALYST`, `NATIONAL_COORDINATOR`, `DSI_ADMIN` |
| Remédiation | `DSI_ADMIN`, `ORGANIZATION_MANAGER` |
| Rédaction d'advisory | `CSIRT_ANALYST`, `NATIONAL_COORDINATOR` |
| Publication | `NATIONAL_COORDINATOR`, `SUPER_ADMIN` |
| Consultation | `AUDITOR` (lecture seule) |

---

## 8. Chronologie type

| Date | Évènement |
|------|-----------|
| J+0 | Rapport reçu |
| J+1 | Accusé de réception |
| J+3 | Vulnérabilité validée |
| J+4 | Organisation contactée |
| J+16 | Correctif fourni |
| J+21 | Correctif vérifié |
| J+26 | Advisory publié |

Seuls les jalons marqués publics alimentent la chronologie de l'advisory.
