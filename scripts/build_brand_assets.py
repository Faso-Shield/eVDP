#!/usr/bin/env python
"""Genere les declinaisons du logo eVDP a partir du master fourni par le design.

Master : docs/brand/logo2-evdp.png.

Deux traitements sont necessaires avant de pouvoir s'en servir.

1. Normalisation du canal alpha. Le master sort d'un detourage automatique :
   le corps du logo plafonne a alpha 250-253 au lieu de 255, ce qui le rend
   legerement translucide, et il subsiste un halo diffus entre alpha 1 et 60
   sur toute la toile. Sur fond clair cela ne se voit pas ; sur le bleu nuit
   de la barre de navigation, le fond transparait a travers le bouclier.
   On remappe donc l'alpha en coupant sous SEUIL_BAS et en saturant au-dessus
   de SEUIL_HAUT, l'anti-crenelage reel etant conserve entre les deux.

2. Variante fond sombre. Dans ce logo le champ du bouclier est transparent et
   le mot est bleu nuit : il est concu pour un fond clair. Sur la barre de
   navigation, l'embleme nu perd son globe et son cadenas. On le pose donc sur
   une tuile claire a coins arrondis, ce qui preserve l'oeuvre a l'identique
   au lieu de la retoucher.

Usage :

    python -m pip install Pillow
    python scripts/build_brand_assets.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

RACINE = Path(__file__).resolve().parent.parent
MASTER = RACINE / "docs" / "brand" / "logo2-evdp.png"
CIBLE = RACINE / "static" / "img"

SEUIL_BAS, SEUIL_HAUT = 30, 235

# Decoupe en L isolant l'embleme du verrouillage complet. Le "e" et la pointe
# de la fleche s'imbriquent : une coupe verticale simple amputerait la fleche.
# Coordonnees exprimees dans le master normalise et recadre (1843 x 713).
EMBLEME_X = 565
FLECHE_X, FLECHE_Y = 720, 255

TUILE_FOND = (238, 243, 248, 255)


def verrouillage() -> Image.Image:
    """Master avec alpha normalise et recadre au contenu."""
    im = Image.open(MASTER).convert("RGBA")
    alpha = im.getchannel("A").point(
        lambda v: (
            0
            if v <= SEUIL_BAS
            else (
                255
                if v >= SEUIL_HAUT
                else round((v - SEUIL_BAS) * 255 / (SEUIL_HAUT - SEUIL_BAS))
            )
        )
    )
    im.putalpha(alpha)
    return im.crop(im.getchannel("A").getbbox())


def embleme(lock: Image.Image) -> Image.Image:
    masque = Image.new("L", lock.size, 0)
    dessin = ImageDraw.Draw(masque)
    dessin.rectangle([0, 0, EMBLEME_X - 1, lock.height], fill=255)
    dessin.rectangle([0, 0, FLECHE_X - 1, FLECHE_Y - 1], fill=255)
    em = lock.copy()
    em.putalpha(Image.composite(em.getchannel("A"), Image.new("L", lock.size, 0), masque))
    return em.crop(em.getchannel("A").getbbox())


def plaque(
    lock: Image.Image,
    hauteur_logo: int,
    pad: float = 0.10,
    extra_droite: float = 0.0,
    fond=TUILE_FOND,
) -> Image.Image:
    """Verrouillage complet sur une plaque claire, pour la barre de navigation.

    Le mot et la baseline sont en bleu nuit : poses nus sur le bleu
    institutionnel ils disparaissent. La plaque restitue le fond clair pour
    lequel le logo a ete dessine, sans retoucher l'oeuvre.

    `extra_droite`, exprime en fraction de la hauteur du logo, allonge la
    plaque vers la droite. C'est la seule facon d'elargir la marque sans
    deformer le dessin, dont les proportions sont celles du master.
    """
    k = hauteur_logo / lock.height
    redim = lock.resize((round(lock.width * k), hauteur_logo), Image.LANCZOS)
    mx, my = round(hauteur_logo * pad * 1.2), round(hauteur_logo * pad)
    mx_droite = mx + round(hauteur_logo * extra_droite)
    largeur, hauteur = redim.width + mx + mx_droite, redim.height + 2 * my

    canevas = Image.new("RGBA", (largeur, hauteur), (0, 0, 0, 0))
    masque = Image.new("L", (largeur * 4, hauteur * 4), 0)
    ImageDraw.Draw(masque).rounded_rectangle(
        [0, 0, largeur * 4 - 1, hauteur * 4 - 1], radius=int(hauteur * 4 * 0.16), fill=255
    )
    canevas.paste(
        Image.new("RGBA", (largeur, hauteur), fond),
        (0, 0),
        masque.resize((largeur, hauteur), Image.LANCZOS),
    )
    canevas.alpha_composite(redim, (mx, my))
    return canevas


def tuile(
    source: Image.Image, taille: int, rayon: float = 0.22, marge: float = 0.09, fond=TUILE_FOND
) -> Image.Image:
    """Embleme centre sur une tuile claire. rayon=0 donne un carre plein."""
    canevas = Image.new("RGBA", (taille, taille), (0, 0, 0, 0))
    if rayon:
        # Masque trace en 4x puis reduit : coins arrondis proprement lisses.
        masque = Image.new("L", (taille * 4, taille * 4), 0)
        ImageDraw.Draw(masque).rounded_rectangle(
            [0, 0, taille * 4 - 1, taille * 4 - 1], radius=int(taille * 4 * rayon), fill=255
        )
        masque = masque.resize((taille, taille), Image.LANCZOS)
    else:
        masque = Image.new("L", (taille, taille), 255)
    canevas.paste(Image.new("RGBA", (taille, taille), fond), (0, 0), masque)

    utile = round(taille * (1 - 2 * marge))
    k = min(utile / source.width, utile / source.height)
    redim = source.resize(
        (max(1, round(source.width * k)), max(1, round(source.height * k))), Image.LANCZOS
    )
    canevas.alpha_composite(redim, ((taille - redim.width) // 2, (taille - redim.height) // 2))
    return canevas


def reduire(image: Image.Image, largeur_max: int) -> Image.Image:
    if image.width <= largeur_max:
        return image
    k = largeur_max / image.width
    return image.resize((largeur_max, max(1, round(image.height * k))), Image.LANCZOS)


def main() -> None:
    lock = verrouillage()
    em = embleme(lock)

    sorties = [
        # Fonds clairs. Le master fait 1843 px de large : on plafonne, sinon
        # l'asset pese 850 ko pour une image jamais affichee au-dela de 900 px.
        ("logo-evdp.png", reduire(lock, 900)),
        ("logo-mark.png", reduire(em, 512)),
        # Fonds sombres et icones : sur tuile claire.
        ("logo-mark-tile.png", tuile(em, 256)),
        # Barre de navigation : logo complet, rendu en 2x pour les ecrans HiDPI.
        # La plaque est allongee vers la droite : seule maniere d'elargir la
        # marque sans etirer le dessin.
        ("logo-evdp-tile.png", plaque(lock, 133, extra_droite=0.25)),
        ("favicon-32.png", tuile(em, 32)),
        ("favicon-192.png", tuile(em, 192)),
        ("logo-512.png", tuile(em, 512)),
        # iOS refuse la transparence et rogne lui-meme les angles.
        ("apple-touch-icon.png", tuile(em, 180, rayon=0, marge=0.12)),
    ]
    for nom, image in sorties:
        image.save(CIBLE / nom, optimize=True)
        print(f"static/img/{nom}  {image.width}x{image.height}")


if __name__ == "__main__":
    main()
