# Identite visuelle eVDP

Ce dossier conserve les fichiers **sources** du logo, tels que fournis par le
design. Ils ne sont jamais servis par l'application : les fichiers reellement
utilises sont generes dans `static/img/` par `scripts/build_brand_assets.py`.

| Fichier | Role |
| --- | --- |
| `logo2-evdp.png` | **Master en vigueur.** Sert de source a toutes les declinaisons. |
| `logo-evdp-background.png` | Master precedent, detoure. Conserve pour historique. |
| `logo-evdp.png` | Mockup de presentation du master precedent, sur fond sombre. Non exploitable comme asset. |

## Regenerer les declinaisons

```bash
python -m pip install Pillow
python scripts/build_brand_assets.py
```

Le script documente les deux traitements appliques au master : normalisation du
canal alpha, et pose sur tuile claire pour les fonds sombres.

## Regles d'emploi

- **Fonds clairs** : `logo-evdp.png` (verrouillage complet) ou `logo-mark.png`
  (embleme seul).
- **Fonds sombres**, dont la barre de navigation : `logo-mark-tile.png`. Le logo
  est concu pour fond clair — champ du bouclier transparent, mot en bleu nuit —
  et disparait s'il est pose nu sur le bleu institutionnel.
- Le verrouillage complet ne descend pas sous ~120 px de haut : en dessous, sa
  baseline devient illisible. Utiliser l'embleme et composer le nom en HTML.
