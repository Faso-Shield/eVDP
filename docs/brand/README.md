# Identite visuelle eVDP

Ce dossier conserve les fichiers **sources** du logo, tels que fournis par le
design. Ils ne sont jamais servis par l'application : les fichiers reellement
utilises sont generes dans `static/img/` par `scripts/build_brand_assets.py`.

| Fichier | Role |
| --- | --- |
| `logo2-evdp.png` | **Master en vigueur.** Sert de source a toutes les declinaisons. |
| `logo-evdp-background.png` | Master precedent, detoure. Conserve pour historique. |

## Regenerer les declinaisons

```bash
python -m pip install Pillow
python scripts/build_brand_assets.py
```

Le script documente les deux traitements appliques au master : normalisation du
canal alpha, et pose sur tuile claire pour les fonds sombres.

## Regles d'emploi

Le logo est dessine pour un fond clair : le champ du bouclier est transparent,
le mot et la baseline sont en bleu nuit. Pose nu sur le bleu institutionnel, il
perd son globe, son cadenas et son texte. Toutes les declinaisons destinees aux
fonds sombres reposent donc sur une plaque ou une tuile claire, qui restitue ce
fond sans retoucher l'oeuvre.

- **Fonds clairs** : `static/img/logo-evdp.png` (verrouillage complet) ou
  `static/img/logo-mark.png` (embleme seul).
- **Barre de navigation** : `static/img/logo-evdp-tile.png`, le verrouillage complet sur
  plaque claire. C'est lui qui porte le nom et la signature de la plateforme :
  aucun texte ne l'accompagne, l'attribut `alt` en tient lieu.
- **Autres fonds sombres**, quand la place manque pour le verrouillage :
  `static/img/logo-mark-tile.png`, l'embleme seul sur tuile.
- La plaque de la navbar est allongee vers la droite. Les proportions du logo
  sont celles du master : l'elargir autrement reviendrait a l'etirer.
- La baseline occupe 6,3 % de la hauteur du verrouillage. A 80 px de plaque,
  la hauteur retenue dans la navbar, elle tourne autour de 4 px : presente et
  reconnaissable, mais elle ne se lit pas. La rendre lisible demanderait une
  plaque d'environ 200 px, donc un en-tete de plus de 200 px, essaye au commit
  5be328c puis abandonne comme trop encombrant.
