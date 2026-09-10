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

Le logo est dessine pour un fond clair : le champ du bouclier est transparent,
le mot et la baseline sont en bleu nuit. Pose nu sur le bleu institutionnel, il
perd son globe, son cadenas et son texte. Toutes les declinaisons destinees aux
fonds sombres reposent donc sur une plaque ou une tuile claire, qui restitue ce
fond sans retoucher l'oeuvre.

- **Fonds clairs** : `logo-evdp.png` (verrouillage complet) ou `logo-mark.png`
  (embleme seul).
- **Barre de navigation** : `logo-evdp-tile.png`, le verrouillage complet sur
  plaque claire. C'est lui qui porte le nom et la signature de la plateforme :
  aucun texte ne l'accompagne, l'attribut `alt` en tient lieu.
- **Autres fonds sombres**, quand la place manque pour le verrouillage :
  `logo-mark-tile.png`, l'embleme seul sur tuile.
- La baseline occupe 6,3 % de la hauteur du verrouillage. A 57 px de haut, la
  hauteur retenue dans la navbar, elle tombe a environ 4 px : elle est presente
  et reconnaissable, mais ne se lit pas. La rendre lisible demanderait un logo
  d'environ 145 px de haut, donc un en-tete nettement plus haut.
