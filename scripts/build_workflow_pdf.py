#!/usr/bin/env python
"""Genere docs/workflow.pdf : manuel du processus de traitement eVDP.

    python scripts/build_workflow_pdf.py [chemin_de_sortie]

Le document decrit le parcours complet d'un signalement, de la soumission a
la cloture, pour les trois profils de declarant (citoyen sans compte,
chercheur inscrit, chercheur Bug Bounty), et detaille pour chaque etape
l'utilisateur metier qui intervient, le moment ou il intervient et l'effet
de son action sur le dossier.

Le contenu est ecrit a la main plutot que derive du code : un manuel doit
expliquer une intention, ce qu'une introspection de la machine a etats ne
produit pas. Les references (statuts, capacites, delais) sont en revanche
celles de `apps.coordination.workflow`, `apps.accounts.roles` et
`apps.coordination.models.SLAPolicy` ; elles sont a reverifier si ces
modules changent.

Seule dependance : reportlab, deja requis par les exports PDF de la
plateforme. Aucune base de donnees n'est ouverte.
"""

import re as _re
import sys
from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

RACINE = Path(__file__).resolve().parent.parent
SORTIE = RACINE / "docs" / "workflow.pdf"

# --------------------------------------------------------------------------
# Identite visuelle : reprise de static/css/evdp.css
# --------------------------------------------------------------------------
NAVY = colors.HexColor("#0b2a4a")
NAVY_CLAIR = colors.HexColor("#123f6d")
ACCENT = colors.HexColor("#0d7a5f")
ACCENT_CLAIR = colors.HexColor("#e6f4ef")
OR = colors.HexColor("#c8901e")
ROUGE = colors.HexColor("#b3261e")
TEXTE = colors.HexColor("#16212d")
MUET = colors.HexColor("#5c6b7d")
BORDURE = colors.HexColor("#d9e1ea")
SURFACE = colors.HexColor("#f8fafc")
BLANC = colors.white

SEV = {
    "critique": colors.HexColor("#8b1a13"),
    "elevee": colors.HexColor("#c1400f"),
    "moyenne": colors.HexColor("#b07d10"),
    "faible": colors.HexColor("#1f6f8b"),
}


def _polices():
    """Enregistre Segoe UI si le systeme la fournit, sinon Helvetica.

    La plateforme s'affiche en Segoe UI : le manuel lui ressemble quand la
    police est disponible, et reste lisible partout sinon.
    """
    fontes = Path("C:/Windows/Fonts")
    fichiers = {
        "EvdpSans": "segoeui.ttf",
        "EvdpSans-Bold": "segoeuib.ttf",
        "EvdpSans-Italic": "segoeuii.ttf",
    }
    try:
        for nom, fichier in fichiers.items():
            chemin = fontes / fichier
            if not chemin.exists():
                raise FileNotFoundError(fichier)
            pdfmetrics.registerFont(TTFont(nom, str(chemin)))
        pdfmetrics.registerFontFamily(
            "EvdpSans",
            normal="EvdpSans",
            bold="EvdpSans-Bold",
            italic="EvdpSans-Italic",
            boldItalic="EvdpSans-Bold",
        )
        return "EvdpSans", "EvdpSans-Bold", "EvdpSans-Italic"
    except Exception:
        return "Helvetica", "Helvetica-Bold", "Helvetica-Oblique"


REGULIER, GRAS, ITALIQUE = _polices()
FLECHE = "\u2192" if REGULIER != "Helvetica" else "->"
PUCE = "\u25aa"


# --------------------------------------------------------------------------
# Styles
# --------------------------------------------------------------------------
def _styles():
    base = ParagraphStyle(
        "corps",
        fontName=REGULIER,
        fontSize=9.4,
        leading=13.6,
        textColor=TEXTE,
        alignment=TA_JUSTIFY,
        spaceAfter=5,
    )
    s = {"corps": base}
    s["chapitre"] = ParagraphStyle(
        "chapitre",
        parent=base,
        fontName=GRAS,
        fontSize=19,
        leading=23,
        textColor=NAVY,
        alignment=0,
        spaceBefore=0,
        spaceAfter=2,
    )
    s["surtitre"] = ParagraphStyle(
        "surtitre",
        parent=base,
        fontName=GRAS,
        fontSize=8,
        leading=11,
        textColor=ACCENT,
        alignment=0,
        spaceAfter=1,
    )
    s["h2"] = ParagraphStyle(
        "h2",
        parent=base,
        fontName=GRAS,
        fontSize=12.6,
        leading=16,
        textColor=NAVY,
        alignment=0,
        spaceBefore=11,
        spaceAfter=4,
    )
    s["h3"] = ParagraphStyle(
        "h3",
        parent=base,
        fontName=GRAS,
        fontSize=10.2,
        leading=13,
        textColor=NAVY_CLAIR,
        alignment=0,
        spaceBefore=8,
        spaceAfter=3,
    )
    s["puce"] = ParagraphStyle(
        "puce",
        parent=base,
        leftIndent=10,
        bulletIndent=1,
        spaceAfter=3,
    )
    s["petit"] = ParagraphStyle(
        "petit", parent=base, fontSize=8.2, leading=11.4, textColor=MUET
    )
    s["cellule"] = ParagraphStyle(
        "cellule", parent=base, fontSize=8.4, leading=11.2, alignment=0, spaceAfter=0
    )
    s["cellule_titre"] = ParagraphStyle(
        "cellule_titre",
        parent=s["cellule"],
        fontName=GRAS,
        textColor=BLANC,
    )
    s["cellule_gras"] = ParagraphStyle("cellule_gras", parent=s["cellule"], fontName=GRAS)
    s["encadre"] = ParagraphStyle(
        "encadre", parent=base, fontSize=8.8, leading=12.4, spaceAfter=3
    )
    s["encadre_titre"] = ParagraphStyle(
        "encadre_titre",
        parent=s["encadre"],
        fontName=GRAS,
        textColor=NAVY,
        spaceAfter=2,
    )
    s["etat"] = ParagraphStyle(
        "etat",
        parent=base,
        fontName=GRAS,
        fontSize=7.4,
        leading=9,
        alignment=TA_CENTER,
        textColor=BLANC,
        spaceAfter=0,
    )
    s["couverture_titre"] = ParagraphStyle(
        "couverture_titre",
        parent=base,
        fontName=GRAS,
        fontSize=30,
        leading=34,
        textColor=BLANC,
        alignment=0,
    )
    s["couverture_sous"] = ParagraphStyle(
        "couverture_sous",
        parent=base,
        fontSize=13,
        leading=18,
        textColor=colors.HexColor("#c7d7e6"),
        alignment=0,
    )
    s["toc1"] = ParagraphStyle(
        "toc1",
        parent=base,
        fontName=GRAS,
        fontSize=10,
        leading=17,
        textColor=NAVY,
        alignment=0,
    )
    s["toc2"] = ParagraphStyle(
        "toc2",
        parent=base,
        fontSize=9,
        leading=13.4,
        leftIndent=12,
        textColor=TEXTE,
        alignment=0,
    )
    return s


S = _styles()


# --------------------------------------------------------------------------
# Briques de mise en page
# --------------------------------------------------------------------------
def p(texte, style="corps"):
    return Paragraph(acc(texte), S[style])


def puces(elements, style="puce"):
    return [
        Paragraph(acc(f"{PUCE}&nbsp;&nbsp;{texte}"), S[style], bulletText=None)
        for texte in elements
    ]


def espace(hauteur=4):
    return Spacer(1, hauteur)


def _c(valeur, style="cellule"):
    """Contenu de cellule : les chaines deviennent des Paragraph."""
    if isinstance(valeur, str):
        return Paragraph(acc(valeur), S[style])
    return valeur


def tableau(entetes, lignes, largeurs, aligne_haut=True, taille_entete=8.4):
    """Tableau institutionnel : en-tete bleu nuit, lignes alternees."""
    donnees = [[_c(e, "cellule_titre") for e in entetes]]
    donnees += [[_c(cellule) for cellule in ligne] for ligne in lignes]
    table = Table(donnees, colWidths=largeurs, repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), BLANC),
        ("FONTNAME", (0, 0), (-1, 0), GRAS),
        ("FONTSIZE", (0, 0), (-1, 0), taille_entete),
        ("VALIGN", (0, 0), (-1, -1), "TOP" if aligne_haut else "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDURE),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for index in range(1, len(donnees)):
        if index % 2 == 0:
            style.append(("BACKGROUND", (0, index), (-1, index), SURFACE))
    table.setStyle(TableStyle(style))
    return table


def encadre(titre, corps, couleur=ACCENT, fond=ACCENT_CLAIR, largeur=170 * mm):
    """Bloc d'attention : filet de couleur a gauche, fond teinte."""
    contenu = [p(titre, "encadre_titre")] if titre else []
    if isinstance(corps, str):
        corps = [corps]
    for element in corps:
        contenu.append(p(element, "encadre") if isinstance(element, str) else element)
    table = Table([[contenu]], colWidths=[largeur], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), fond),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, couleur),
                ("BOX", (0, 0), (-1, -1), 0.4, BORDURE),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def flux(etats, par_ligne=4, largeur=170 * mm, couleur=NAVY):
    """Suite d'etats relies par des fleches, repliee sur plusieurs lignes."""
    blocs = []
    for depart in range(0, len(etats), par_ligne):
        tranche = etats[depart : depart + par_ligne]
        cellules, styles = [], []
        largeur_fleche = 7 * mm
        largeurs = []
        for index, etat in enumerate(tranche):
            colonne = len(cellules)
            cellules.append(Paragraph(etat, S["etat"]))
            styles.append(("BACKGROUND", (colonne, 0), (colonne, 0), couleur))
            styles.append(("ROUNDEDCORNERS", [3, 3, 3, 3]))
            largeurs.append(None)
            if index < len(tranche) - 1:
                cellules.append(Paragraph(FLECHE, S["etat"]))
                styles.append(
                    ("TEXTCOLOR", (len(cellules) - 1, 0), (len(cellules) - 1, 0), MUET)
                )
                largeurs.append(largeur_fleche)
        reste = largeur - largeur_fleche * (len(tranche) - 1)
        largeurs = [reste / len(tranche) if v is None else v for v in largeurs]
        table = Table([cellules], colWidths=largeurs, hAlign="LEFT")
        table.setStyle(
            TableStyle(
                styles
                + [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 3),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        blocs.append(table)
        blocs.append(espace(3))
    return KeepTogether(blocs)


def fiche_etape(numero, titre, meta, contenu, largeur=170 * mm):
    """Fiche d'etape : bandeau numerote, tableau Qui/Quand/Ou, puis corps.

    `meta` est une liste de couples (intitule, valeur) ; le tableau est la
    reponse en un coup d'oeil aux trois questions du manuel : qui agit, a
    quel moment, et depuis quel ecran.
    """
    bandeau = Table(
        [
            [
                Paragraph(str(numero), S["couverture_titre"]),
                Paragraph(acc(titre), S["chapitre"]),
            ]
        ],
        colWidths=[16 * mm, largeur - 16 * mm],
        hAlign="LEFT",
    )
    bandeau.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), NAVY),
                ("BACKGROUND", (1, 0), (1, 0), SURFACE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                ("LEFTPADDING", (1, 0), (1, 0), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -1), 1.2, NAVY),
            ]
        )
    )
    lignes = [[_c(f"<b>{intitule}</b>"), _c(valeur)] for intitule, valeur in meta]
    fiche = Table(lignes, colWidths=[28 * mm, largeur - 28 * mm], hAlign="LEFT")
    fiche.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), SURFACE),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDURE),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    # Le bandeau, sa fiche et le premier paragraphe restent solidaires :
    # une etape annoncee en bas de page, corps a la page suivante, se lit mal.
    tete = [bandeau, espace(5), fiche, espace(6)]
    contenu = list(contenu)
    if contenu:
        tete.append(contenu.pop(0))
    return [KeepTogether(tete)] + contenu


# --------------------------------------------------------------------------
# Gabarit du document : couverture, en-tetes, pagination
# --------------------------------------------------------------------------
TITRE = "Manuel du processus de traitement"
SOUS_TITRE = "eVDP - Plateforme nationale de divulgation coordonnee"


class Canevas:
    """Fabrique de canevas numerotant les pages en deux passes.

    Le nombre total de pages n'est connu qu'a la fin : les pages sont donc
    gardees en memoire, puis ecrites une fois le compte arrete.
    """

    def __init__(self, *args, **kwargs):
        raise NotImplementedError


def _fabrique_canevas():
    from reportlab.pdfgen import canvas as canvas_module

    class CanevasNumerote(canvas_module.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for etat in self._pages:
                self.__dict__.update(etat)
                if self._pageNumber > 1:
                    self._pied(total)
                super().showPage()
            super().save()

        def _pied(self, total):
            largeur, _ = A4
            self.setStrokeColor(BORDURE)
            self.setLineWidth(0.6)
            self.line(18 * mm, 14 * mm, largeur - 18 * mm, 14 * mm)
            self.setFont(REGULIER, 7.4)
            self.setFillColor(MUET)
            self.drawString(
                18 * mm,
                10 * mm,
                "eVDP - Manuel du processus de traitement  |  Diffusion interne",
            )
            self.setFont(GRAS, 7.4)
            self.setFillColor(NAVY)
            self.drawRightString(
                largeur - 18 * mm, 10 * mm, f"{self._pageNumber - 1} / {total - 1}"
            )

    return CanevasNumerote


def _entete(canevas, doc):
    """Bandeau superieur des pages de contenu."""
    largeur, hauteur = A4
    canevas.saveState()
    canevas.setFillColor(NAVY)
    canevas.rect(0, hauteur - 13 * mm, largeur, 13 * mm, stroke=0, fill=1)
    canevas.setFillColor(BLANC)
    canevas.setFont(GRAS, 8.2)
    canevas.drawString(18 * mm, hauteur - 8.6 * mm, "eVDP")
    canevas.setFont(REGULIER, 8.2)
    canevas.setFillColor(colors.HexColor("#c7d7e6"))
    canevas.drawString(30 * mm, hauteur - 8.6 * mm, TITRE)
    canevas.setFillColor(ACCENT)
    canevas.rect(0, hauteur - 13.9 * mm, largeur, 0.9 * mm, stroke=0, fill=1)
    canevas.restoreState()


def _couverture(canevas, doc):
    """Premiere page : aplat bleu nuit, titre, pied institutionnel."""
    largeur, hauteur = A4
    canevas.saveState()
    canevas.setFillColor(NAVY)
    canevas.rect(0, hauteur - 148 * mm, largeur, 148 * mm, stroke=0, fill=1)
    canevas.setFillColor(ACCENT)
    canevas.rect(0, hauteur - 152 * mm, largeur, 4 * mm, stroke=0, fill=1)

    canevas.setFillColor(colors.HexColor("#7fb3a3"))
    canevas.setFont(GRAS, 10)
    canevas.drawString(22 * mm, hauteur - 34 * mm, "eVDP")
    canevas.setFillColor(colors.HexColor("#c7d7e6"))
    canevas.setFont(REGULIER, 10)
    canevas.drawString(
        36 * mm, hauteur - 34 * mm, "Plateforme nationale de divulgation coordonnee"
    )

    canevas.setFillColor(BLANC)
    canevas.setFont(GRAS, 31)
    canevas.drawString(22 * mm, hauteur - 62 * mm, "Manuel du processus")
    canevas.drawString(22 * mm, hauteur - 75 * mm, "de traitement")

    canevas.setFillColor(ACCENT)
    canevas.rect(22 * mm, hauteur - 85 * mm, 46 * mm, 1.4 * mm, stroke=0, fill=1)

    canevas.setFillColor(colors.HexColor("#c7d7e6"))
    canevas.setFont(REGULIER, 13)
    canevas.drawString(22 * mm, hauteur - 98 * mm, "Du signalement a la cloture du dossier")
    canevas.setFont(REGULIER, 10.5)
    for index, ligne in enumerate(
        [
            "Workflow complet, roles metiers, actions et delais",
            "Citoyen sans compte  |  Chercheur en securite  |  Chercheur Bug Bounty",
        ]
    ):
        canevas.drawString(22 * mm, hauteur - (110 + index * 6.5) * mm, ligne)

    canevas.setFillColor(MUET)
    canevas.setFont(REGULIER, 9)
    canevas.drawString(22 * mm, 26 * mm, f"Version 1.0  -  {date.today():%d/%m/%Y}")
    canevas.drawString(22 * mm, 20 * mm, "Diffusion interne - Ne pas publier en l'etat")
    canevas.setStrokeColor(BORDURE)
    canevas.line(22 * mm, 32 * mm, A4[0] - 22 * mm, 32 * mm)
    canevas.restoreState()


class Document(BaseDocTemplate):
    """Gabarit a deux modeles de page : couverture puis contenu."""

    def __init__(self, chemin, **kwargs):
        super().__init__(
            str(chemin),
            pagesize=A4,
            title="eVDP - Manuel du processus de traitement",
            author="eVDP",
            subject="Workflow de traitement des signalements de vulnerabilite",
            leftMargin=20 * mm,
            rightMargin=20 * mm,
            topMargin=22 * mm,
            bottomMargin=20 * mm,
            **kwargs,
        )
        cadre_couverture = Frame(
            20 * mm, 20 * mm, A4[0] - 40 * mm, A4[1] - 40 * mm, id="couverture"
        )
        cadre_contenu = Frame(
            20 * mm,
            18 * mm,
            A4[0] - 40 * mm,
            A4[1] - 40 * mm,
            id="contenu",
            topPadding=0,
        )
        self.addPageTemplates(
            [
                PageTemplate("couverture", [cadre_couverture], onPage=_couverture),
                PageTemplate("contenu", [cadre_contenu], onPage=_entete),
            ]
        )

    def afterFlowable(self, flowable):
        """Alimente le sommaire depuis les titres rencontres.

        Le folio imprime ignore la couverture : le sommaire doit citer le
        meme numero que le pied de page, soit la page physique moins une.
        """
        if not isinstance(flowable, Paragraph):
            return
        niveaux = {"chapitre": 0, "h2": 1}
        niveau = niveaux.get(flowable.style.name)
        if niveau is not None:
            self.notify("TOCEntry", (niveau, flowable.getPlainText(), self.page - 1))


def chapitre(numero, titre, surtitre=""):
    """Ouvre un chapitre sur une nouvelle page."""
    blocs = [PageBreak()]
    if surtitre:
        blocs.append(p(acc(surtitre).upper(), "surtitre"))
    blocs.append(Paragraph(acc(f"{numero}. {titre}"), S["chapitre"]))
    filet = Table([[""]], colWidths=[38 * mm], rowHeights=[1.6 * mm], hAlign="LEFT")
    filet.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), ACCENT)]))
    blocs.append(filet)
    blocs.append(espace(8))
    return blocs


# ==========================================================================
# Contenu
# ==========================================================================
L = 170 * mm  # largeur utile


def sommaire():
    toc = TableOfContents()
    toc.levelStyles = [S["toc1"], S["toc2"]]
    toc.dotsMinLevel = 0
    return [
        NextPageTemplate("contenu"),
        PageBreak(),
        p("Sommaire", "chapitre"),
        espace(8),
        toc,
    ]


def chapitre_1():
    blocs = chapitre(1, "Objet du manuel", "Lire ce document")
    blocs += [
        p(
            "Ce manuel decrit le traitement d'un signalement de vulnerabilite sur eVDP, "
            "depuis le moment ou une personne decouvre une faille jusqu'a la cloture du "
            "dossier. Il repond a trois questions pour chaque etape : <b>qui agit</b>, "
            "<b>a quel moment</b>, et <b>quel effet</b> son action produit sur le dossier "
            "et sur les personnes qui le suivent."
        ),
        p(
            "Il couvre les trois profils de declarant que la plateforme accepte - un "
            "citoyen sans compte, un chercheur en securite inscrit, un chercheur "
            "participant a un programme Bug Bounty - et les roles metiers qui "
            "interviennent ensuite."
        ),
        p("A qui il s'adresse", "h2"),
        tableau(
            ["Lecteur", "Ce qu'il y trouve", "Chapitres"],
            [
                [
                    "Agent de triage, analyste CSIRT",
                    "La sequence de traitement quotidienne, les delais a tenir, les "
                    "ecrans et les actions correspondantes.",
                    "5 a 9",
                ],
                [
                    "Coordinateur national",
                    "Les decisions qui lui sont reservees : approbation d'une "
                    "recompense, publication d'un advisory, arbitrage des delais.",
                    "8, 9, 13",
                ],
                [
                    "DSI, responsable d'organisation",
                    "Ce qu'on attend de son entite une fois contactee, et dans quels "
                    "delais.",
                    "7, 10, 12",
                ],
                [
                    "Declarant (citoyen, chercheur)",
                    "Comment signaler, ce qu'il recoit en retour, ce qu'il peut suivre.",
                    "4, 5, 12",
                ],
                [
                    "Auditeur, direction",
                    "La chaine de responsabilite, la tracabilite et les indicateurs.",
                    "3, 11, 13",
                ],
            ],
            [42 * mm, L - 64 * mm, 22 * mm],
        ),
        espace(8),
        p("Conventions", "h2"),
    ]
    blocs += puces(
        [
            "Les <b>capacites</b> sont citees telles qu'elles figurent dans la "
            "plateforme, en majuscules : <b>TRIAGE_CASE</b>, <b>APPROVE_BOUNTY</b>. Une "
            "capacite est l'autorisation elementaire verifiee par le serveur ; un role "
            "en est un ensemble.",
            "Les <b>statuts de dossier</b> sont cites en majuscules : <b>VALIDATED</b>, "
            "<b>FIX_VERIFIED</b>. Leur libelle francais est celui affiche a l'ecran.",
            "Les <b>ecrans</b> sont designes par leur adresse : <b>/cases/kanban/</b>, "
            "<b>/bounties/</b>. Le menu lateral y mene selon le role.",
            "Un <b>dossier</b> porte la reference <b>EVDP-AAAA-NNNNNN</b>. C'est l'objet "
            "de travail ; le <b>rapport</b> est la matiere brute deposee par le "
            "declarant, que le traitement ne modifie jamais.",
        ]
    )
    blocs += [
        espace(6),
        encadre(
            "Deux regles valables partout dans ce manuel",
            [
                "<b>1. Le role n'est jamais lu depuis le navigateur.</b> Il vient de la "
                "base de donnees, et chaque action est reverifiee par le serveur. Une "
                "entree de menu absente n'est pas une simple mise en forme : l'adresse "
                "saisie a la main est refusee de la meme facon, et le refus est "
                "journalise.",
                "<b>2. Un dossier est prive par defaut.</b> Rien n'est publie "
                "automatiquement, a aucune etape. La publication est un acte explicite, "
                "reserve a un role precis, et elle porte sur un advisory redige pour "
                "l'occasion - jamais sur le rapport d'origine.",
            ],
        ),
    ]
    return blocs


def chapitre_2():
    blocs = chapitre(2, "Le processus en une page", "Vue d'ensemble")
    blocs += [
        p(
            "Six phases separent la decouverte d'une faille de la cloture de son "
            "dossier. Les deux premieres appartiennent au declarant et a l'equipe de "
            "triage, les trois suivantes a la coordination et a l'organisation affectee, "
            "la derniere a la publication."
        ),
        espace(4),
        tableau(
            ["Phase", "Qui agit", "Delai vise", "Etat a la sortie"],
            [
                [
                    "<b>1. Signalement</b><br/>Le declarant depose son rapport",
                    "Citoyen, chercheur, chercheur Bug Bounty",
                    "-",
                    "SUBMITTED",
                ],
                [
                    "<b>2. Reception</b><br/>Prise en charge et accuse de reception",
                    "Agent de triage, analyste CSIRT",
                    "72 heures",
                    "RECEIVED puis ACKNOWLEDGED",
                ],
                [
                    "<b>3. Triage</b><br/>Qualification technique et decision",
                    "Agent de triage, analyste CSIRT, coordinateur",
                    "5 jours",
                    "VALIDATED, ou une issue de triage",
                ],
                [
                    "<b>4. Coordination</b><br/>L'organisation affectee est contactee",
                    "Analyste CSIRT, coordinateur ; reponse de la DSI",
                    "7 jours pour la reponse",
                    "VENDOR_CONTACTED, VENDOR_ACKNOWLEDGED",
                ],
                [
                    "<b>5. Remediation</b><br/>Correction puis verification",
                    "DSI et responsable d'organisation, avec l'analyste",
                    "30 a 90 jours selon la severite",
                    "FIX_AVAILABLE puis FIX_VERIFIED",
                ],
                [
                    "<b>6. Divulgation</b><br/>Advisory redige, relu, publie",
                    "Analyste CSIRT puis coordinateur national",
                    "90 jours apres validation, par defaut",
                    "DISCLOSURE_SCHEDULED, PUBLISHED, CLOSED",
                ],
            ],
            [46 * mm, 40 * mm, 28 * mm, L - 114 * mm],
        ),
        espace(10),
        p("Le parcours nominal d'un dossier", "h2"),
        flux(
            [
                "SUBMITTED",
                "RECEIVED",
                "ACKNOWLEDGED",
                "TRIAGE",
                "VALIDATED",
                "VENDOR_CONTACTED",
                "REMEDIATION",
                "FIX_AVAILABLE",
                "VERIFICATION",
                "FIX_VERIFIED",
                "DISCLOSURE_SCHEDULED",
                "PUBLISHED",
                "CLOSED",
            ],
            par_ligne=4,
        ),
        espace(4),
        p(
            "Toute transition non prevue est refusee par le serveur et tracee comme un "
            "refus dans le journal d'audit. Le chapitre 6 donne la table complete des "
            "passages autorises ; le chapitre 8 decrit les issues qui interrompent ce "
            "parcours : doublon, rejet, hors perimetre, sans objet, informatif.",
            "petit",
        ),
        espace(8),
        p("Ce qui se declenche sans intervention humaine", "h2"),
        p(
            "Trois automatismes tournent en arriere-plan. Ils expliquent la plupart des "
            "notifications recues sans qu'un collegue ait touche au dossier."
        ),
        tableau(
            ["Automatisme", "Frequence", "Effet"],
            [
                [
                    "<b>Surveillance des echeances</b>",
                    "Toutes les 30 minutes",
                    "Marque l'echeance <b>proche</b> a 80 % du delai, puis <b>depassee</b> "
                    "au terme. Notifie l'equipe du dossier et augmente son score de "
                    "priorite de 10 points.",
                ],
                [
                    "<b>Veille des divulgations</b>",
                    "Quotidienne",
                    "Alerte l'equipe sur les divulgations prevues dans les sept jours et "
                    "non encore publiees.",
                ],
                [
                    "<b>Recalcul des priorites</b>",
                    "Quotidienne",
                    "Reevalue le score 0-100 de chaque dossier ouvert : severite, secteur "
                    "de l'organisation, anciennete, depassements d'echeance.",
                ],
            ],
            [44 * mm, 30 * mm, L - 74 * mm],
        ),
    ]
    return blocs


def chapitre_3():
    blocs = chapitre(3, "Les acteurs et leurs droits", "Qui est qui")
    blocs += [
        p(
            "Dix roles coexistent sur la plateforme. Ils se rangent en quatre familles "
            "dont les droits ne se recouvrent pas : personne ne cumule le depot d'un "
            "signalement et son arbitrage."
        ),
        p("3.1 Les quatre familles", "h2"),
        tableau(
            ["Famille", "Roles", "Perimetre de visibilite", "Second facteur"],
            [
                [
                    "<b>Declarants</b>",
                    "Utilisateur public, Chercheur en securite, Chercheur Bug Bounty",
                    "Uniquement leurs propres dossiers.",
                    "Non exige",
                ],
                [
                    "<b>Equipe nationale</b>",
                    "Agent de triage, Analyste CSIRT, Coordinateur national",
                    "Tous les dossiers de la plateforme.",
                    "<b>Obligatoire</b>",
                ],
                [
                    "<b>Organisation affectee</b>",
                    "Administrateur DSI, Responsable d'organisation",
                    "Les dossiers de leurs organisations, et ceux ou ils sont "
                    "participants.",
                    "<b>Obligatoire</b>",
                ],
                [
                    "<b>Transverses</b>",
                    "Auditeur (lecture seule), Administrateur systeme",
                    "Tous les dossiers ; l'auditeur n'ecrit rien.",
                    "<b>Obligatoire</b>",
                ],
            ],
            [30 * mm, 46 * mm, L - 100 * mm, 24 * mm],
        ),
        espace(6),
        encadre(
            "Double authentification : la frontiere est le role",
            "Tout compte metier - triage, analyse, coordination, DSI, audit, "
            "administration - doit enroler un authentificateur TOTP et valider un code a "
            "chaque session : tant que le second facteur n'est pas fourni, seules les "
            "pages d'enrolement, de verification et de deconnexion repondent. Les comptes "
            "declarants en sont dispenses : leur exiger un authentificateur "
            "decouragerait le signalement, qui est le but de la plateforme.",
            couleur=NAVY_CLAIR,
            fond=colors.HexColor("#eef4fa"),
        ),
        espace(8),
        p("3.2 Ce que chaque role fait dans le processus", "h2"),
        tableau(
            ["Role", "Son role dans le traitement", "Interventions"],
            [
                [
                    "<b>Agent de triage</b><br/>TRIAGER",
                    "Premiere ligne. Accuse reception, qualifie, decide de l'issue de "
                    "triage. N'assigne pas et ne coordonne pas.",
                    "Etapes 1, 3, 4",
                ],
                [
                    "<b>Analyste CSIRT</b><br/>CSIRT_ANALYST",
                    "Conduit le dossier de bout en bout : qualification, assignation, "
                    "contact de l'organisation, suivi de la correction, redaction de "
                    "l'advisory, proposition de recompense.",
                    "Etapes 1 a 8",
                ],
                [
                    "<b>Coordinateur national</b><br/>NATIONAL_COORDINATOR",
                    "Arbitre et signe. Seul, avec l'administrateur, a approuver une "
                    "recompense, a publier un advisory et a lire les messages restreints.",
                    "Etapes 4, 7, 8, 9",
                ],
                [
                    "<b>Administrateur DSI</b><br/>DSI_ADMIN",
                    "Represente l'entite affectee : accuse reception du contact, pilote "
                    "la correction, declare le correctif disponible.",
                    "Etapes 5, 6",
                ],
                [
                    "<b>Responsable d'organisation</b><br/>ORGANIZATION_MANAGER",
                    "Meme perimetre que la DSI, oriente gestion : membres, programmes, "
                    "perimetres et propositions de recompense de son entite.",
                    "Etapes 5, 6",
                ],
                [
                    "<b>Auditeur</b><br/>AUDITOR",
                    "Lit tout, n'ecrit rien : dossiers, journal d'audit, tableaux de bord, "
                    "exports. Toute tentative d'ecriture est refusee.",
                    "Controle a posteriori",
                ],
                [
                    "<b>Administrateur systeme</b><br/>SUPER_ADMIN",
                    "Detient toutes les capacites. Cree les comptes metiers, les "
                    "organisations, les politiques de delai. N'intervient pas dans le "
                    "traitement courant.",
                    "Parametrage",
                ],
                [
                    "<b>Chercheur / Utilisateur public</b>",
                    "Depose un signalement, repond aux demandes d'information, verifie le "
                    "correctif si on le lui demande. Ne voit que ses dossiers.",
                    "Etapes 0, 3, 7",
                ],
            ],
            [40 * mm, L - 68 * mm, 28 * mm],
        ),
        espace(8),
        p("3.3 Qui peut faire quoi", "h2"),
        p(
            "Chaque action du traitement exige une capacite precise. Le tableau se lit "
            "colonne par colonne : un point signifie que le serveur accepte l'action "
            "pour ce role.",
            "petit",
        ),
        matrice_capacites(),
        espace(6),
        p(
            "Deux consequences pratiques. Un <b>agent de triage</b> qualifie et decide, "
            "mais n'assigne pas un dossier a un collegue : la repartition de la charge "
            "reste a l'analyste ou au coordinateur. Une <b>DSI</b> fait avancer la "
            "correction mais ne valide ni ne rejette un signalement : la qualification "
            "reste nationale, pour qu'une entite ne puisse pas ecarter ce qui la "
            "concerne.",
        ),
    ]
    return blocs


def matrice_capacites():
    """Matrice action x role. Lignes courtes : elle doit rester lisible."""
    roles = ["Triage", "Analyste", "Coord.", "DSI / Resp.", "Auditeur"]
    lignes = [
        ("Voir tous les dossiers", [1, 1, 1, 0, 1]),
        ("Voir les dossiers de son organisation", [1, 1, 1, 1, 1]),
        ("Changer le statut d'un dossier", [1, 1, 1, 1, 0]),
        ("Qualifier, valider, rejeter (triage)", [1, 1, 1, 0, 0]),
        ("Definir la severite retenue", [1, 1, 1, 0, 0]),
        ("Assigner un dossier", [0, 1, 1, 0, 0]),
        ("Publier un message interne", [1, 1, 1, 1, 0]),
        ("Proposer une recompense", [0, 1, 1, 1, 0]),
        ("Approuver une recompense", [0, 0, 1, 0, 0]),
        ("Enregistrer un versement", [0, 0, 1, 0, 0]),
        ("Rediger un advisory", [0, 1, 1, 0, 0]),
        ("Publier un advisory", [0, 0, 1, 0, 0]),
        ("Gerer un programme", [0, 1, 1, 1, 0]),
        ("Consulter le journal d'audit", [0, 0, 1, 0, 1]),
        ("Exporter des donnees", [0, 1, 1, 1, 1]),
    ]
    marque = "●" if REGULIER != "Helvetica" else "X"
    corps = []
    for intitule, cases in lignes:
        corps.append([intitule] + [marque if c else "" for c in cases])
    largeurs = [L - 5 * 19 * mm] + [19 * mm] * 5
    donnees = [[_c(e, "cellule_titre") for e in ["Action"] + roles]]
    for ligne in corps:
        donnees.append([_c(ligne[0])] + [_c(f"<b>{v}</b>" if v else "") for v in ligne[1:]])
    table = Table(donnees, colWidths=largeurs, repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("FONTNAME", (0, 0), (-1, 0), GRAS),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDURE),
        ("TEXTCOLOR", (1, 1), (-1, -1), ACCENT),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]
    for index in range(1, len(donnees)):
        if index % 2 == 0:
            style.append(("BACKGROUND", (0, index), (-1, index), SURFACE))
    table.setStyle(TableStyle(style))
    return table


def chapitre_4():
    blocs = chapitre(4, "Avant le premier signalement", "Preparation")
    blocs += [
        p(
            "Un signalement n'arrive pas dans le vide : il vise une organisation "
            "referencee, souvent un programme publie, et il est traite selon une "
            "politique de delais. Ces trois objets sont crees par des utilisateurs "
            "metiers, avant tout depot."
        ),
        p("4.1 Ce que le public voit et qui le prepare", "h2"),
        tableau(
            ["Ce que le public trouve", "Adresse", "Prepare par"],
            [
                [
                    "Politique de divulgation : engagement de l'Etat, regles de test, "
                    "delais annonces",
                    "/disclosure-policy/",
                    "Coordinateur national, administrateur",
                ],
                [
                    "Fichier security.txt et cle PGP nationale, pour un signalement "
                    "chiffre",
                    "/.well-known/security.txt<br/>/pgp-key.asc",
                    "Administrateur",
                ],
                [
                    "Annuaire des programmes VDP et Bug Bounty ouverts",
                    "/programs/",
                    "Analyste CSIRT, DSI, responsable d'organisation (capacite "
                    "MANAGE_PROGRAM)",
                ],
                [
                    "Annuaire des organisations participantes",
                    "/organizations/",
                    "Coordinateur national, responsable d'organisation",
                ],
                [
                    "Advisories publies et classement des chercheurs",
                    "/advisories/<br/>/researchers/",
                    "Publies a l'issue du processus (chapitre 8)",
                ],
            ],
            [58 * mm, 42 * mm, L - 100 * mm],
        ),
        espace(8),
        p("4.2 Creer une organisation", "h2"),
        p(
            "L'organisation porte le secteur, le statut et surtout ses <b>membres</b> : "
            "responsable, DSI, contact securite. Ce point est decisif pour la suite - "
            "ce sont ces trois profils que la plateforme rattache automatiquement a "
            "tout dossier concernant l'entite. Une organisation sans contact designe "
            "recevra bien le dossier, mais personne ne le verra de son cote."
        ),
        tableau(
            ["Qui", "Où", "Ce qu'il renseigne"],
            [
                [
                    "Coordinateur national, administrateur (MANAGE_ALL_ORGANIZATIONS)",
                    "/organizations/manage/new/",
                    "Nom, sigle, type, secteur, statut, contact securite, acceptation du "
                    "dispositif VDP.",
                ],
                [
                    "Responsable d'organisation, DSI (MANAGE_ORGANIZATION)",
                    "/organizations/manage/",
                    "Met a jour sa propre fiche et ses membres : responsable, DSI, "
                    "contact securite, analyste, observateur.",
                ],
            ],
            [56 * mm, 40 * mm, L - 96 * mm],
        ),
        espace(8),
        p("4.3 Creer un programme : VDP ou Bug Bounty", "h2"),
        p(
            "Le programme decide de deux choses qui pesent sur tout le traitement : "
            "<b>qui a le droit de signaler</b>, et <b>quel delai de divulgation</b> "
            "s'appliquera une fois le dossier valide."
        ),
        tableau(
            ["", "Programme VDP", "Programme Bug Bounty"],
            [
                [
                    "<b>But</b>",
                    "Recueillir les signalements sur un perimetre large.",
                    "Susciter la recherche sur un perimetre cible et delimite.",
                ],
                [
                    "<b>Signalement anonyme</b>",
                    "Accepte par defaut.",
                    "<b>Refuse</b> : on ne recompense pas un chercheur qu'on ne peut pas "
                    "identifier.",
                ],
                [
                    "<b>Compte et adresse verifiee</b>",
                    "Non exiges (reglage possible).",
                    "<b>Exiges</b>, sans exception possible.",
                ],
                [
                    "<b>Recompense</b>",
                    "Aucune.",
                    "Matrice par severite, affinable par actif du perimetre.",
                ],
                [
                    "<b>Workflow</b>",
                    "Divulgation coordonnee classique.",
                    "Idem, plus les etapes severite attribuee, revue et approbation de "
                    "recompense.",
                ],
            ],
            [34 * mm, (L - 34 * mm) / 2, (L - 34 * mm) / 2],
        ),
        espace(5),
        p(
            "Le programme porte aussi les <b>regles de test</b>, le <b>safe harbor</b> - "
            "l'engagement de ne pas poursuivre un chercheur qui respecte les regles -, "
            "le perimetre <b>inclus</b> et <b>exclu</b> actif par actif, la politique de "
            "delais applicable et le delai de divulgation (90 jours par defaut).",
        ),
        espace(4),
        encadre(
            "Le statut du programme conditionne la reception",
            "Un programme n'accepte des signalements que s'il est <b>actif</b> et dans sa "
            "fenetre de dates. Suspendu, clos ou encore en brouillon, il refuse le depot "
            "avec un message explicite - et l'annonce sur sa fiche publique, avant que le "
            "chercheur ait redige quoi que ce soit.",
            couleur=OR,
            fond=colors.HexColor("#fdf6e0"),
        ),
        espace(8),
        p("4.4 Fixer les delais", "h2"),
        p(
            "Une politique de delais rassemble les echeances appliquees aux dossiers. "
            "Un programme peut avoir la sienne ; sinon la politique par defaut "
            "s'applique. Valeurs livrees :"
        ),
        tableau(
            ["Echeance", "Delai par defaut", "Point de depart", "Soldee par"],
            [
                [
                    "Accuse de reception",
                    "72 heures",
                    "Depot du signalement",
                    "Passage en RECEIVED ou ACKNOWLEDGED",
                ],
                [
                    "Premier triage",
                    "5 jours",
                    "Depot du signalement",
                    "Passage en TRIAGE ou toute decision de triage",
                ],
                [
                    "Reponse de l'organisation",
                    "7 jours",
                    "Contact de l'organisation",
                    "Accuse de reception de l'organisation",
                ],
                [
                    "Remediation",
                    "30 j (critique et elevee)<br/>60 j (moyenne)<br/>90 j (faible)",
                    "Validation, ou entree en remediation",
                    "Correctif disponible ou verifie",
                ],
                [
                    "Divulgation",
                    "Date planifiee",
                    "Planification de la divulgation",
                    "Publication de l'advisory",
                ],
            ],
            [38 * mm, 38 * mm, 42 * mm, L - 118 * mm],
        ),
        espace(4),
        p(
            "Une alerte est levee des 80 % du delai consomme. Le seuil, comme les delais, "
            "se modifie dans l'administration : rien n'est fige dans le code.",
            "petit",
        ),
    ]
    return blocs


def chapitre_5():
    blocs = chapitre(5, "Le signalement : trois portes d'entree", "Etape 0")
    blocs += [
        p(
            "La plateforme accepte un signalement de trois facons, selon qui le depose. "
            "Le formulaire est le meme ; ce sont les conditions d'acces, le suivi offert "
            "et les suites possibles qui different."
        ),
        espace(2),
        tableau(
            [
                "",
                "Citoyen sans compte",
                "Chercheur inscrit",
                "Chercheur Bug Bounty",
            ],
            [
                [
                    "<b>Compte requis</b>",
                    "Non",
                    "Oui",
                    "Oui, avec adresse verifiee",
                ],
                [
                    "<b>Anonymat</b>",
                    "Possible, total ou avec adresse de contact",
                    "Possible au titre du credit public",
                    "Impossible",
                ],
                [
                    "<b>Programmes accessibles</b>",
                    "VDP acceptant l'anonymat",
                    "Tous les programmes VDP",
                    "Bug Bounty, plus les VDP",
                ],
                [
                    "<b>Suivi du dossier</b>",
                    "Par courriel, si une adresse a ete laissee",
                    "Espace personnel, messagerie, notifications",
                    "Idem, plus le suivi de la recompense",
                ],
                [
                    "<b>Reputation</b>",
                    "Non",
                    "Oui, a la validation",
                    "Oui, plus les montants percus",
                ],
                [
                    "<b>Recompense</b>",
                    "Non",
                    "Non",
                    "Oui, selon la matrice du programme",
                ],
            ],
            [30 * mm, (L - 30 * mm) / 3, (L - 30 * mm) / 3, (L - 30 * mm) / 3],
        ),
        espace(8),
        p("5.1 Le citoyen sans compte", "h2"),
        p(
            "Un agent public, un usager, un informaticien de passage remarque une anomalie "
            "et veut la signaler sans creer de compte. Il ouvre <b>/report/</b> depuis le "
            "bandeau Signaler."
        ),
    ]
    blocs += puces(
        [
            "Il decrit la vulnerabilite : titre, organisation affectee ou programme, "
            "produit, adresse concernee, description (30 caracteres au minimum), etapes "
            "de reproduction, impact, recommandations. Le Markdown est accepte.",
            "Il indique une <b>adresse de contact</b>, ou coche <b>signalement "
            "anonyme</b>. L'un des deux est obligatoire : sans rien, le formulaire "
            "refuse.",
            "Il peut joindre jusqu'a cinq fichiers, et coller un <b>bloc PGP chiffre</b> "
            "si le contenu est trop sensible pour etre stocke en clair.",
            "Il accepte la politique de divulgation : la case est obligatoire et son "
            "acceptation est conservee avec le rapport.",
        ]
    )
    blocs += [
        espace(3),
        p(
            "A l'envoi, il obtient une page de confirmation portant la <b>reference "
            "EVDP-AAAA-NNNNNN</b>, a conserver, et l'annonce du delai de 72 heures. La "
            "page lui propose de creer un compte pour suivre le dossier."
        ),
        encadre(
            "Anonymat total : le silence est le prix",
            "Sans compte et sans adresse de contact, la plateforme n'a aucun moyen de "
            "joindre le declarant : il ne recevra ni accuse de reception, ni demande "
            "d'information, ni avis de publication. C'est un choix legitime, mais il "
            "faut le connaitre. Une adresse de contact, meme jetable, suffit a ouvrir le "
            "canal de retour sans rien reveler de l'identite.",
            couleur=OR,
            fond=colors.HexColor("#fdf6e0"),
        ),
        espace(8),
        p("5.2 Le chercheur en securite inscrit", "h2"),
        p(
            "Le chercheur cree son compte sur <b>/register/</b>, choisit son <b>mode "
            "d'identite</b> - nom public, pseudonyme, ou anonyme - et recoit un courriel "
            "de verification. Ce mode d'identite est celui qui sera repris dans le credit "
            "public de l'advisory, des mois plus tard."
        ),
    ]
    blocs += puces(
        [
            "Il depose depuis le meme formulaire, sans avoir a saisir d'adresse de "
            "contact : son compte fait foi.",
            "A l'envoi, il est conduit directement sur le <b>dossier</b>, ou il verra "
            "l'etat, la chronologie, les echeances et la messagerie.",
            "Il recoit une notification interne et un courriel a chaque evolution : "
            "accuse de reception, demande d'information, validation, rejet, publication.",
            "Il peut demander l'attribution d'un <b>CVE</b> et declarer s'il souhaite "
            "etre <b>credite publiquement</b>.",
            "La validation de son rapport lui attribue des <b>points de reputation</b>, "
            "majores pour une severite elevee ou critique. Ces points ne sont jamais "
            "modifiables a la main par le chercheur.",
        ]
    )
    blocs += [
        espace(8),
        p("5.3 Le chercheur Bug Bounty", "h2"),
        p(
            "Le chercheur Bug Bounty part du programme, pas du formulaire : il lit la "
            "fiche publique sur <b>/programs/</b>, le perimetre inclus et exclu, les "
            "regles de test, le safe harbor et la grille de recompense, puis depose "
            "depuis la fiche - le programme est alors pre-selectionne."
        ),
        tableau(
            ["Condition", "Pourquoi", "Ce qui se passe si elle manque"],
            [
                [
                    "Etre connecte avec un compte",
                    "Une recompense se verse a une personne identifiee.",
                    "Le depot est refuse, avec l'invitation a se connecter. Le message "
                    "apparait <b>des l'ouverture du formulaire</b>, pas apres redaction.",
                ],
                [
                    "Adresse email verifiee",
                    "Personne ne doit pouvoir encaisser au nom d'une adresse qu'il ne "
                    "controle pas.",
                    "Le depot est refuse et renvoie vers le profil, ou la verification se "
                    "relance en un clic.",
                ],
                [
                    "Programme ouvert",
                    "Une campagne a des dates.",
                    "Le depot est refuse : programme suspendu, clos ou hors periode.",
                ],
                [
                    "Cible dans le perimetre",
                    "Le hors-perimetre est annonce a l'avance.",
                    "Le depot est accepte, mais le triage conclura <b>hors perimetre</b> "
                    "et le dossier sera clos sans recompense.",
                ],
            ],
            [40 * mm, 44 * mm, L - 84 * mm],
        ),
        espace(4),
        p(
            "Les comptes crees avant l'entree en vigueur de l'exigence de verification "
            "beneficient d'un <b>sursis</b> : ils participent encore pendant un delai "
            "defini, sont relances par courriel, et le CSIRT dispose d'un export de ceux "
            "dont le sursis expire - une adresse jamais verifiee peut etre une adresse "
            "morte, que la relance automatique ne touchera jamais.",
            "petit",
        ),
        espace(8),
        p("5.4 Les deux autres canaux", "h2"),
        tableau(
            ["Canal", "Pour qui", "Particularite"],
            [
                [
                    "<b>API v1</b><br/>/api/v1/reports/",
                    "Outillage d'un chercheur, integration d'un CERT partenaire",
                    "Meme service de soumission que le formulaire : memes controles, meme "
                    "ouverture de dossier, memes notifications.",
                ],
                [
                    "<b>Import CSAF</b><br/>/api/v1/import/csaf/",
                    "Equipe nationale (capacite IMPORT_CSAF)",
                    "Reprise d'un avis de securite au format normalise, transmis par un "
                    "editeur ou un CERT etranger.",
                ],
            ],
            [42 * mm, 48 * mm, L - 90 * mm],
        ),
        espace(8),
        p("5.5 Ce que la plateforme fait a la seconde du depot", "h2"),
        p(
            "Le depot n'est pas un simple enregistrement : neuf operations s'enchainent "
            "dans une seule transaction. Les connaitre evite de chercher a la main ce qui "
            "est deja fait."
        ),
        tableau(
            ["", "Operation", "Consequence pour le traitement"],
            [
                [
                    "1",
                    "Le rapport est enregistre, <b>prive</b>, avec l'empreinte de l'adresse "
                    "IP du depot - jamais l'adresse elle-meme.",
                    "La matiere brute est figee : elle ne sera plus modifiee par personne.",
                ],
                [
                    "2",
                    "Un <b>dossier EVDP-AAAA-NNNNNN</b> est ouvert au statut SUBMITTED.",
                    "C'est lui que l'equipe traite ; la reference sert dans tous les "
                    "echanges.",
                ],
                [
                    "3",
                    "Le <b>workflow</b> est choisi : Bug Bounty si le programme en est un, "
                    "divulgation coordonnee sinon.",
                    "Il determine les etats atteignables pour toute la vie du dossier.",
                ],
                [
                    "4",
                    "La <b>severite initiale</b> est calculee depuis le vecteur CVSS "
                    "fourni, ou reprise de l'estimation du declarant.",
                    "Elle sera revue au triage ; elle sert entretemps au classement.",
                ],
                [
                    "5",
                    "La chronologie s'ouvre sur <b>Rapport recu</b>.",
                    "Premier jalon, public : il figurera dans l'advisory.",
                ],
                [
                    "6",
                    "Les <b>participants</b> sont rattaches : le declarant, puis le "
                    "responsable, la DSI et le contact securite de l'organisation visee.",
                    "Ce sont eux qui recevront les notifications et verront le dossier.",
                ],
                [
                    "7",
                    "Les echeances <b>72 heures</b> et <b>5 jours</b> sont armees.",
                    "Le compte a rebours commence, meme la nuit et le week-end.",
                ],
                [
                    "8",
                    "Le <b>score de priorite</b> est calcule.",
                    "Il classe le dossier dans la file de traitement.",
                ],
                [
                    "9",
                    "Notifications : l'<b>equipe de triage</b> est prevenue, le declarant "
                    "recoit son accuse de depot ; le depot est journalise.",
                    "Personne n'a besoin de surveiller une boite aux lettres.",
                ],
            ],
            [7 * mm, 76 * mm, L - 83 * mm],
        ),
    ]
    return blocs


def chapitre_6():
    blocs = chapitre(
        6, "Le traitement, etape par etape", "Du dossier recu au correctif verifie"
    )
    blocs += [
        p(
            "Chaque etape est presentee de la meme facon : qui agit, quand, depuis quel "
            "ecran, avec quelle autorisation, et ce que l'action produit. Les etapes 1 a "
            "4 se deroulent au CSIRT, les etapes 5 a 7 avec l'organisation affectee, les "
            "etapes 8 et 9 avec la coordination nationale."
        ),
        espace(6),
    ]

    # -- Etape 1 ------------------------------------------------------------
    blocs += fiche_etape(
        1,
        "Prise en charge et accuse de reception",
        [
            ("Qui", "Agent de triage, analyste CSIRT, coordinateur national"),
            ("Quand", "Dans les <b>72 heures</b> suivant le depot"),
            ("Où", "/cases/ (file triee par priorite) ou /cases/kanban/, colonne Soumis"),
            ("Autorisation", "CHANGE_CASE_STATUS"),
            ("Transition", "SUBMITTED " + FLECHE + " RECEIVED " + FLECHE + " ACKNOWLEDGED"),
        ],
        [
            p(
                "Le dossier arrive dans la colonne <b>Soumis</b> du tableau Kanban et en "
                "tete de la file si sa severite annoncee est haute. L'agent l'ouvre, lit "
                "le rapport, verifie qu'il est exploitable - une description vide de "
                "sens, un doublon evident, un contenu hors sujet se voient des la "
                "premiere lecture - puis le passe en <b>Recu</b>, et <b>Accuse de "
                "reception</b> une fois le declarant informe."
            ),
            espace(2),
            tableau(
                ["Ce que l'action declenche", "Detail"],
                [
                    [
                        "L'echeance de 72 heures est soldee",
                        "Elle disparait des echeances a risque ; le dossier cesse "
                        "d'alimenter les alertes de retard sur ce point.",
                    ],
                    [
                        "Le declarant est notifie",
                        "Notification interne et courriel s'il a un compte ; courriel "
                        "seul s'il a laisse une adresse ; rien s'il est totalement "
                        "anonyme.",
                    ],
                    [
                        "La chronologie est completee",
                        "Jalon <b>Accuse de reception</b>, public : il figurera dans "
                        "l'advisory final.",
                    ],
                    [
                        "L'historique retient l'auteur",
                        "Ancien statut, nouveau statut, auteur, horodatage, commentaire "
                        "eventuel.",
                    ],
                ],
                [52 * mm, L - 52 * mm],
            ),
            espace(3),
            encadre(
                "Accuser reception n'est pas valider",
                "L'accuse de reception dit seulement : nous avons lu, nous traitons. Il "
                "n'engage sur aucune qualification. Le declarant est informe par un "
                "message neutre ; c'est au triage, ensuite, de dire si la vulnerabilite "
                "est retenue.",
                couleur=NAVY_CLAIR,
                fond=colors.HexColor("#eef4fa"),
            ),
        ],
    )

    # -- Etape 2 ------------------------------------------------------------
    blocs += fiche_etape(
        2,
        "Assignation a un analyste",
        [
            ("Qui", "Analyste CSIRT, coordinateur national"),
            ("Quand", "Des la prise en charge, avant le travail de qualification"),
            ("Où", "Fiche du dossier, bloc <b>Assignation</b>"),
            ("Autorisation", "ASSIGN_CASE"),
            ("Transition", "Aucune : le statut ne change pas"),
        ],
        [
            p(
                "L'assignation designe le responsable du dossier. Elle n'est pas "
                "obligatoire pour avancer, mais un dossier sans titulaire est un dossier "
                "que personne ne surveille : c'est le premier reflexe d'organisation de "
                "la file."
            ),
            espace(2),
        ]
        + puces(
            [
                "L'analyste designe devient <b>participant</b> du dossier et recoit une "
                "notification d'assignation.",
                "Toute assignation anterieure est desactivee : un seul titulaire a la "
                "fois, et l'historique conserve la suite des passations.",
                "L'<b>agent de triage</b> ne dispose pas de cette capacite : il qualifie, "
                "mais ne repartit pas la charge de l'equipe.",
            ]
        ),
    )
    blocs.append(espace(10))

    # -- Etape 3 ------------------------------------------------------------
    blocs += fiche_etape(
        3,
        "Qualification technique",
        [
            ("Qui", "Agent de triage, analyste CSIRT, coordinateur national"),
            ("Quand", "Dans les <b>5 jours</b> suivant le depot"),
            ("Où", "Fiche du dossier, bloc <b>Qualification</b>"),
            ("Autorisation", "TRIAGE_CASE, et SET_SEVERITY pour la severite"),
            ("Transition", "vers TRIAGE, puis vers la decision de l'etape 4"),
        ],
        [
            p(
                "La qualification est le travail d'expertise du CSIRT : elle transforme "
                "une declaration en dossier exploitable. Six champs sont a renseigner."
            ),
            espace(2),
            tableau(
                ["Champ", "Ce qu'il engage pour la suite"],
                [
                    [
                        "<b>Severite retenue</b>",
                        "Elle commande le delai de correction (30, 60 ou 90 jours), le "
                        "score de priorite, le palier de recompense et les points de "
                        "reputation du chercheur. C'est la decision la plus lourde de "
                        "l'etape.",
                    ],
                    [
                        "<b>Vecteur CVSS v3.1</b>",
                        "S'il est fourni, le score est recalcule par la plateforme et la "
                        "severite peut en decouler. Un vecteur mal forme est refuse a la "
                        "saisie.",
                    ],
                    [
                        "<b>CWE</b>",
                        "Classe la faiblesse ; alimente les statistiques nationales et "
                        "l'advisory.",
                    ],
                    [
                        "<b>Organisation affectee</b>",
                        "Souvent absente ou approximative dans le rapport. La corriger "
                        "ici <b>ouvre le dossier aux contacts de l'entite</b> : c'est ce "
                        "qui rend la coordination possible.",
                    ],
                    [
                        "<b>Actif du perimetre</b>",
                        "Sur un programme, designe la cible concernee. Determine la "
                        "grille de recompense quand elle varie par actif.",
                    ],
                    [
                        "<b>Etiquettes</b>",
                        "Douze au maximum. Servent au filtrage et aux regroupements par "
                        "campagne ou par technologie.",
                    ],
                ],
                [40 * mm, L - 40 * mm],
            ),
            espace(3),
            p(
                "Si le rapport est incomplet, le dossier passe en <b>Informations "
                "demandees</b> : le declarant recoit une notification dediee et repond "
                "par la messagerie du dossier. L'echeance de triage, elle, continue de "
                "courir - le chapitre 9 explique comment le suivre.",
            ),
        ],
    )

    # -- Etape 4 ------------------------------------------------------------
    blocs += fiche_etape(
        4,
        "La decision de triage",
        [
            ("Qui", "Agent de triage, analyste CSIRT, coordinateur national"),
            ("Quand", "A l'issue de la qualification, dans les 5 jours"),
            ("Où", "Fiche du dossier, bloc <b>Changer le statut</b>"),
            ("Autorisation", "TRIAGE_CASE"),
            ("Transition", "TRIAGE " + FLECHE + " VALIDATED, ou une issue de triage"),
        ],
        [
            p(
                "C'est le point de bascule du dossier : soit la vulnerabilite est "
                "retenue et le processus de correction s'engage, soit le dossier prend "
                "une issue qui le referme. Six sorties sont possibles."
            ),
            espace(2),
            tableau(
                ["Decision", "Quand la retenir", "Suite"],
                [
                    [
                        "<b>Valide</b>",
                        "La vulnerabilite est reelle, reproductible, dans le perimetre.",
                        "Le traitement continue a l'etape 5.",
                    ],
                    [
                        "<b>Doublon</b>",
                        "Le meme defaut est deja suivi dans un autre dossier.",
                        "Dossier clos. Le declarant est informe du doublon, <b>sans "
                        "jamais connaitre le dossier d'origine</b>.",
                    ],
                    [
                        "<b>Rejete</b>",
                        "Le defaut n'est pas demontre, ou le rapport n'est pas "
                        "exploitable.",
                        "Dossier clos, notification au declarant.",
                    ],
                    [
                        "<b>Hors perimetre</b>",
                        "La cible ne figure pas dans le perimetre du programme.",
                        "Dossier clos ; aucune recompense possible.",
                    ],
                    [
                        "<b>Non applicable</b>",
                        "Comportement conforme, protection deja en place, risque "
                        "inexistant.",
                        "Dossier clos.",
                    ],
                    [
                        "<b>Informatif</b>",
                        "Constat utile, sans vulnerabilite exploitable.",
                        "Le dossier reste ouvert puis est clos ; il alimente les "
                        "statistiques.",
                    ],
                ],
                [26 * mm, 62 * mm, L - 88 * mm],
            ),
            espace(4),
            p("Ce que la validation declenche", "h3"),
            tableau(
                ["Effet", "Detail"],
                [
                    [
                        "Date de validation posee",
                        "Elle sert de reference a tous les delais qui suivent.",
                    ],
                    [
                        "<b>Date de divulgation calculee</b>",
                        "Validation plus le delai du programme, 90 jours par defaut. "
                        "Elle est modifiable ensuite, mais elle existe des maintenant : "
                        "l'organisation sait de combien de temps elle dispose.",
                    ],
                    [
                        "<b>Echeance de correction armee</b>",
                        "30 jours (critique, elevee), 60 (moyenne) ou 90 (faible), selon "
                        "la severite retenue a l'etape 3.",
                    ],
                    [
                        "<b>Reputation attribuee</b>",
                        "Points de base au chercheur, majores pour une severite elevee ou "
                        "critique. L'attribution n'a lieu qu'une fois par dossier.",
                    ],
                    [
                        "Declarant notifie",
                        "Message de validation, distinct de l'accuse de reception.",
                    ],
                ],
                [46 * mm, L - 46 * mm],
            ),
            espace(3),
            encadre(
                "Sur un programme Bug Bounty, la suite differe",
                "Apres la validation, le dossier ne part pas directement en coordination : "
                "il passe par <b>Severite attribuee</b>, puis par la <b>revue de "
                "recompense</b> et l'<b>approbation</b>. Ces trois etats n'existent pas "
                "dans le workflow de divulgation coordonnee - la machine a etats les "
                "refuse. Voir le chapitre 7.",
                couleur=OR,
                fond=colors.HexColor("#fdf6e0"),
            ),
        ],
    )

    # -- Etape 5 ------------------------------------------------------------
    blocs += fiche_etape(
        5,
        "Coordination avec l'organisation affectee",
        [
            ("Qui", "Analyste CSIRT ou coordinateur national ; reponse de la DSI"),
            ("Quand", "Des la validation. L'organisation repond sous <b>7 jours</b>"),
            ("Où", "Fiche du dossier : statut, puis messagerie securisee"),
            ("Autorisation", "CHANGE_CASE_STATUS"),
            (
                "Transition",
                "VALIDATED " + FLECHE + " VENDOR_CONTACTED " + FLECHE + " VENDOR_ACKNOWLEDGED",
            ),
        ],
        [
            p(
                "L'organisation affectee entre ici dans le dossier. Elle y a acces parce "
                "que ses contacts en sont participants depuis l'ouverture, ou parce que "
                "le triage lui a rattache le dossier a l'etape 3."
            ),
            espace(2),
            p("Cote CSIRT", "h3"),
        ]
        + puces(
            [
                "Passer le dossier en <b>Organisation contactee</b> : l'echeance de "
                "reponse de 7 jours s'arme aussitot.",
                "Ecrire le premier message au niveau <b>Participants</b> : c'est le seul "
                "niveau que la DSI et le declarant lisent.",
                "Preciser ce qui est attendu : accuse de reception, interlocuteur "
                "technique, delai de correction envisage.",
            ]
        )
        + [
            espace(3),
            p("Cote organisation", "h3"),
        ]
        + puces(
            [
                "L'administrateur DSI ou le responsable d'organisation ouvre le dossier "
                "depuis <b>/dashboard/organization/</b>, qui ne montre que les "
                "vulnerabilites de son entite.",
                "Il repond par la messagerie, puis passe le dossier en <b>Organisation a "
                "accuse reception</b> : l'echeance de 7 jours est soldee.",
                "Il peut deposer des pieces jointes - plan de correction, captures, note "
                "technique.",
            ]
        )
        + [
            espace(3),
            encadre(
                "Le choix du niveau de message est un acte de confidentialite",
                "Trois niveaux coexistent sur la meme page. <b>Participants</b> est lu par "
                "le declarant et par l'organisation. <b>Interne CSIRT</b> ne sort pas de "
                "l'equipe nationale. <b>Restreint</b> n'est lu que par la coordination "
                "nationale. Le niveau se choisit avant d'envoyer, et il ne se corrige "
                "pas apres.",
                couleur=ROUGE,
                fond=colors.HexColor("#fbe9e7"),
            ),
        ],
    )
    blocs.append(espace(8))

    # -- Etape 6 ------------------------------------------------------------
    blocs += fiche_etape(
        6,
        "Remediation",
        [
            ("Qui", "Administrateur DSI, responsable d'organisation, avec l'analyste"),
            (
                "Quand",
                "<b>30 jours</b> (critique, elevee), <b>60</b> (moyenne), <b>90</b> "
                "(faible) apres la validation",
            ),
            ("Où", "Fiche du dossier, bloc <b>Changer le statut</b> et messagerie"),
            ("Autorisation", "CHANGE_CASE_STATUS"),
            (
                "Transition",
                "REMEDIATION " + FLECHE + " FIX_AVAILABLE",
            ),
        ],
        [
            p(
                "L'entite corrige. La plateforme ne fait pas le travail a sa place : elle "
                "tient le delai, garde la trace des echanges et previent quand "
                "l'echeance approche."
            ),
            espace(2),
        ]
        + puces(
            [
                "L'organisation tient le dossier a jour par la messagerie : diagnostic, "
                "contournement provisoire, date de mise en production.",
                "Une alerte part a <b>80 %</b> du delai consomme, une seconde au "
                "depassement. Le depassement ajoute 10 points au score de priorite : le "
                "dossier remonte dans la file de tout le monde.",
                "Quand le correctif est en place, le dossier passe en <b>Correctif "
                "disponible</b>. L'echeance de correction est alors soldee.",
            ]
        )
        + [
            espace(3),
            p(
                "Un delai intenable se negocie <b>dans le dossier</b>, par un message "
                "argumente, et non par l'oubli de l'echeance : le coordinateur peut "
                "repousser la date de divulgation (etape 8), ce qui laisse une trace "
                "datee de la decision et de son motif.",
                "petit",
            ),
        ],
    )

    # -- Etape 7 ------------------------------------------------------------
    blocs += fiche_etape(
        7,
        "Verification du correctif",
        [
            ("Qui", "Analyste CSIRT ; le chercheur est associe a la contre-verification"),
            ("Quand", "Des l'annonce du correctif"),
            ("Où", "Fiche du dossier"),
            ("Autorisation", "CHANGE_CASE_STATUS"),
            (
                "Transition",
                "FIX_AVAILABLE "
                + FLECHE
                + " VERIFICATION "
                + FLECHE
                + " FIX_VERIFIED, ou retour en REMEDIATION",
            ),
        ],
        [
            p(
                "La verification est ce qui distingue un dossier clos d'un dossier "
                "resolu. Le declarant d'origine est le mieux place pour dire si le "
                "contournement tient : l'analyste lui demande son avis par la messagerie, "
                "au niveau Participants."
            ),
            espace(2),
        ]
        + puces(
            [
                "Si le correctif tient : <b>Correctif verifie</b>. La date de remediation "
                "est posee et le dossier est pret pour la divulgation.",
                "Si le correctif ne tient pas : retour en <b>Remediation en cours</b>. La "
                "machine a etats autorise explicitement ce retour arriere - c'est le seul "
                "du parcours nominal.",
                "Un dossier qui n'appelle aucune publication peut etre <b>clos</b> "
                "directement depuis cet etat.",
            ]
        ),
    )
    blocs.append(espace(10))

    # -- Transitions --------------------------------------------------------
    blocs += [
        p("6.1 Table des passages autorises", "h2"),
        p(
            "La machine a etats n'accepte que les passages listes ci-dessous. Tout autre "
            "essai est refuse avec un message explicite, et le refus est inscrit au "
            "journal d'audit - y compris lorsqu'il vient d'une adresse forgee a la main.",
            "petit",
        ),
        espace(2),
        tableau(
            ["Depuis", "Vers (divulgation coordonnee)", "Vers (Bug Bounty)"],
            [
                ["SUBMITTED", "RECEIVED, TRIAGE", "RECEIVED, TRIAGE"],
                ["RECEIVED", "ACKNOWLEDGED, TRIAGE", "ACKNOWLEDGED, TRIAGE"],
                ["ACKNOWLEDGED", "TRIAGE", "TRIAGE"],
                [
                    "TRIAGE",
                    "NEEDS_INFORMATION, VALIDATED, et les cinq issues de triage",
                    "Idem",
                ],
                [
                    "NEEDS_INFORMATION",
                    "TRIAGE, et les cinq issues de triage",
                    "Idem",
                ],
                [
                    "VALIDATED",
                    "IN_PROGRESS, VENDOR_CONTACTED, NEEDS_INFORMATION, DUPLICATE",
                    "<b>SEVERITY_ASSIGNED</b>, NEEDS_INFORMATION, DUPLICATE",
                ],
                ["SEVERITY_ASSIGNED", "-", "BOUNTY_REVIEW, REMEDIATION"],
                ["BOUNTY_REVIEW", "-", "REWARD_APPROVED, REMEDIATION"],
                ["REWARD_APPROVED", "-", "REMEDIATION"],
                ["IN_PROGRESS", "VENDOR_CONTACTED, REMEDIATION", "-"],
                [
                    "VENDOR_CONTACTED",
                    "VENDOR_ACKNOWLEDGED, REMEDIATION, DISCLOSURE_SCHEDULED",
                    "-",
                ],
                ["VENDOR_ACKNOWLEDGED", "REMEDIATION", "-"],
                [
                    "REMEDIATION",
                    "FIX_AVAILABLE, DISCLOSURE_SCHEDULED",
                    "FIX_AVAILABLE, VERIFICATION",
                ],
                ["FIX_AVAILABLE", "VERIFICATION", "VERIFICATION"],
                ["VERIFICATION", "FIX_VERIFIED, REMEDIATION", "FIX_VERIFIED, REMEDIATION"],
                ["FIX_VERIFIED", "DISCLOSURE_SCHEDULED, CLOSED", "Idem"],
                ["DISCLOSURE_SCHEDULED", "PUBLISHED, CLOSED", "Idem"],
                ["PUBLISHED", "CLOSED", "CLOSED"],
                ["INFORMATIVE", "CLOSED", "CLOSED"],
                [
                    "CLOSED, REJECTED, DUPLICATE,<br/>OUT_OF_SCOPE, NOT_APPLICABLE",
                    "<i>Aucune : etats terminaux</i>",
                    "<i>Aucune</i>",
                ],
            ],
            [44 * mm, (L - 44 * mm) / 2, (L - 44 * mm) / 2],
        ),
        espace(4),
        p(
            "Les cinq issues de triage sont : DUPLICATE, REJECTED, OUT_OF_SCOPE, "
            "NOT_APPLICABLE et INFORMATIVE. Quatre d'entre elles sont terminales ; "
            "INFORMATIVE conduit a la cloture.",
            "petit",
        ),
    ]
    return blocs


def chapitre_7():
    blocs = chapitre(7, "La branche Bug Bounty : la recompense", "Etapes 4 bis")
    blocs += [
        p(
            "Sur un programme Bug Bounty, la validation ouvre une sequence "
            "supplementaire avant la correction : attribuer la severite definitive, "
            "proposer un montant, le faire approuver, puis enregistrer le versement. "
            "Cette sequence obeit a une regle de separation stricte : <b>celui qui "
            "propose n'approuve pas</b>."
        ),
        espace(4),
        flux(
            [
                "VALIDATED",
                "SEVERITY_ASSIGNED",
                "BOUNTY_REVIEW",
                "REWARD_APPROVED",
                "REMEDIATION",
            ],
            par_ligne=5,
            couleur=ACCENT,
        ),
        espace(6),
        p("7.1 Qui fait quoi", "h2"),
        tableau(
            ["Acte", "Qui en a le droit", "Autorisation", "Effet"],
            [
                [
                    "<b>Proposer</b> un montant",
                    "Analyste CSIRT, coordinateur national, DSI, responsable "
                    "d'organisation",
                    "PROPOSE_BOUNTY",
                    "Cree la recompense au statut <b>Proposee</b> et notifie le " "chercheur.",
                ],
                [
                    "<b>Donner un avis</b>",
                    "Memes profils",
                    "PROPOSE_BOUNTY",
                    "Avis favorable, defavorable, ajustement ou commentaire. Fait passer "
                    "la recompense en <b>En revue</b>.",
                ],
                [
                    "<b>Approuver</b> ou <b>rejeter</b>",
                    "<b>Coordinateur national, administrateur uniquement</b>",
                    "APPROVE_BOUNTY",
                    "Fixe le montant definitif, date et signe la decision, notifie le "
                    "chercheur.",
                ],
                [
                    "<b>Enregistrer le versement</b>",
                    "Coordinateur national, administrateur",
                    "RECORD_PAYMENT",
                    "Trace comptable du paiement effectue hors plateforme ; la "
                    "recompense passe a <b>Payee</b>.",
                ],
            ],
            [30 * mm, 38 * mm, 34 * mm, L - 102 * mm],
        ),
        espace(4),
        encadre(
            "Un analyste ne peut pas approuver ce qu'il a propose",
            "La capacite d'approbation n'est accordee ni a l'analyste CSIRT, ni a la DSI, "
            "ni au responsable d'organisation. Le refus est prononce par le serveur, pas "
            "par l'interface : il tient meme si la requete est forgee. La decision "
            "financiere reste ainsi separee de l'expertise technique qui la motive.",
        ),
        espace(8),
        p("7.2 D'ou vient le montant propose", "h2"),
        p(
            "Le montant n'est jamais invente : il vient de la <b>matrice du programme</b>, "
            "qui associe a chaque severite un palier minimum et maximum. Un actif du "
            "perimetre peut avoir son propre palier - une faille critique sur une API de "
            "production ne vaut pas la meme chose que sur un site vitrine. C'est l'actif "
            "retenu au triage (etape 3) qui selectionne la grille ; a defaut, celle du "
            "programme s'applique. La plateforme propose par defaut la borne haute du "
            "palier ; l'analyste peut la reduire."
        ),
        espace(2),
        tableau(
            ["Situation", "Ce que fait la plateforme"],
            [
                [
                    "Montant dans le palier de la severite",
                    "Approbation ordinaire.",
                ],
                [
                    "<b>Montant hors palier</b>",
                    "L'approbation reste possible - les situations exceptionnelles "
                    "existent - mais elle est <b>signalee a l'ecran</b> et "
                    "<b>journalisee avec un avertissement</b> explicite.",
                ],
                [
                    "Chercheur sans adresse verifiee",
                    "La proposition est <b>refusee</b>. Le controle est refait ici, apres "
                    "celui du depot : le programme a pu devenir plus exigeant entre-temps.",
                ],
                [
                    "Dossier sans chercheur identifie",
                    "La proposition est refusee : aucune recompense sans destinataire.",
                ],
                [
                    "Programme sans matrice active",
                    "Montant suggere nul ; le montant doit etre saisi et justifie a la "
                    "main.",
                ],
            ],
            [52 * mm, L - 52 * mm],
        ),
        espace(8),
        p("7.3 Cycle de vie de la recompense", "h2"),
        flux(
            ["PROPOSÉE", "EN REVUE", "APPROUVÉE", "PAYÉE"],
            par_ligne=4,
            couleur=ACCENT,
        ),
        p(
            "Depuis <b>Proposee</b> ou <b>En revue</b>, la recompense peut aussi etre "
            "<b>rejetee</b> ou <b>annulee</b> ; ces deux etats sont definitifs, comme "
            "<b>Payee</b>. Une recompense deja tranchee ne peut plus etre reproposee.",
            "petit",
        ),
        espace(6),
        p("7.4 Le paiement", "h2"),
        p(
            "La plateforme <b>n'execute aucun flux financier</b>. Le versement est realise "
            "hors plateforme par le service financier - virement bancaire, mobile money - "
            "puis enregistre ici : montant, devise, moyen, reference externe, agent "
            "ayant saisi, date. Cette trace est ce qui permet le rapprochement "
            "comptable, et c'est elle qui fait passer la recompense a <b>Payee</b>."
        ),
        espace(2),
        p(
            "Le chercheur suit l'ensemble depuis son espace : montant propose, decision, "
            "versement, et cumul percu. Chaque changement lui vaut une notification."
        ),
        espace(4),
        encadre(
            "La recompense ne remplace pas la correction",
            "Une recompense approuvee n'arrete pas le dossier : il repart en "
            "<b>Remediation</b>, puis suit le meme chemin qu'un dossier de divulgation "
            "coordonnee jusqu'a la verification, la publication eventuelle et la cloture. "
            "Payer n'est pas corriger.",
            couleur=NAVY_CLAIR,
            fond=colors.HexColor("#eef4fa"),
        ),
    ]
    return blocs


def chapitre_8():
    blocs = chapitre(8, "Divulgation, publication et cloture", "Etapes 8 et 9")

    blocs += fiche_etape(
        8,
        "Planifier la divulgation et rediger l'advisory",
        [
            ("Qui", "Analyste CSIRT redige ; <b>coordinateur national publie</b>"),
            ("Quand", "Apres verification du correctif, a la date planifiee"),
            (
                "Où",
                "Fiche du dossier (date, CVE) ; /advisories/manage/ pour la redaction",
            ),
            ("Autorisation", "CHANGE_CASE_STATUS, DRAFT_ADVISORY, PUBLISH_ADVISORY"),
            (
                "Transition",
                "FIX_VERIFIED " + FLECHE + " DISCLOSURE_SCHEDULED " + FLECHE + " PUBLISHED",
            ),
        ],
        [
            p(
                "La divulgation est le seul moment ou une information sort du cercle des "
                "participants. Elle se prepare en quatre temps."
            ),
            espace(2),
            tableau(
                ["", "Acte", "Qui", "Detail"],
                [
                    [
                        "1",
                        "<b>Fixer la date</b>",
                        "Analyste, coordinateur",
                        "Une date pre-calculee existe depuis la validation. La confirmer "
                        "ou la deplacer arme l'echeance de divulgation et inscrit le "
                        "jalon dans la chronologie.",
                    ],
                    [
                        "2",
                        "<b>Associer un CVE</b>",
                        "Analyste, coordinateur",
                        "Si un identifiant a ete obtenu, il est rattache au dossier et "
                        "reporte dans l'advisory.",
                    ],
                    [
                        "3",
                        "<b>Rediger l'advisory</b>",
                        "Analyste CSIRT",
                        "Depuis le dossier, l'action <b>Rediger un advisory</b> prepare "
                        "un brouillon <b>assaini</b> : titre, produit, severite, CVSS, "
                        "CWE, CVE, credit du chercheur et chronologie publique. Ni "
                        "preuve de concept, ni etapes de reproduction, ni URL cible ne "
                        "sont repris.",
                    ],
                    [
                        "4",
                        "<b>Relire puis publier</b>",
                        "Analyste puis coordinateur",
                        "Brouillon, puis En relecture, puis Approuve. La publication "
                        "elle-meme est reservee au coordinateur national.",
                    ],
                ],
                [7 * mm, 32 * mm, 30 * mm, L - 69 * mm],
            ),
            espace(4),
            p("Le cycle de l'advisory", "h3"),
            flux(
                ["BROUILLON", "EN RELECTURE", "APPROUVÉ", "PLANIFIÉ", "PUBLIÉ"],
                par_ligne=5,
                couleur=NAVY_CLAIR,
            ),
            p(
                "Un advisory publie peut etre <b>retire</b>, avec motif obligatoire ; le "
                "retrait est journalise. Un resume public vide interdit la publication.",
                "petit",
            ),
            espace(4),
            p("Controle avant publication", "h3"),
        ]
        + puces(
            [
                "Aucune preuve de concept, aucune etape de reproduction exploitable.",
                "Aucune URL interne, aucun identifiant de dossier.",
                "Le correctif est effectivement disponible et verifie.",
                "L'organisation affectee connait la date et l'a acceptee.",
                "Le <b>credit</b> respecte le choix du chercheur : nom public, "
                "pseudonyme, ou <b>Chercheur anonyme</b> s'il a demande l'anonymat ou "
                "refuse le credit.",
                "La severite, le CVSS et le CWE publies correspondent a ceux retenus au "
                "triage.",
            ]
        )
        + [
            espace(3),
            p(
                "A la publication, le dossier passe en <b>Publie</b>, la chronologie "
                "s'enrichit du jalon correspondant et le chercheur est notifie avec le "
                "lien vers l'advisory. La chronologie publique ne reprend que les jalons "
                "marques publics : rapport recu, accuse de reception, validation, "
                "organisation contactee, correctif fourni, correctif verifie, advisory "
                "publie.",
            ),
        ],
    )
    blocs.append(espace(10))

    blocs += fiche_etape(
        9,
        "Cloture du dossier",
        [
            ("Qui", "Analyste CSIRT, coordinateur national"),
            ("Quand", "Apres publication, ou des la verification si rien n'est publie"),
            ("Où", "Fiche du dossier, bloc <b>Changer le statut</b>"),
            ("Autorisation", "CHANGE_CASE_STATUS"),
            (
                "Transition",
                "PUBLISHED, FIX_VERIFIED ou DISCLOSURE_SCHEDULED " + FLECHE + " CLOSED",
            ),
        ],
        [
            p("La cloture solde le dossier. Elle produit quatre effets."),
            espace(2),
        ]
        + puces(
            [
                "La date de cloture est posee et le dossier quitte les files de travail.",
                "<b>Toutes les echeances encore en cours sont annulees</b> : le dossier "
                "cesse d'alimenter les alertes de retard.",
                "Le jalon de cloture rejoint la chronologie, et l'historique conserve qui "
                "a clos, quand et pourquoi.",
                "L'etat est <b>terminal</b> : aucune transition ne part d'un dossier clos. "
                "Une reprise suppose un nouveau dossier, rattache au precedent.",
            ]
        )
        + [
            espace(4),
            encadre(
                "Tout n'a pas vocation a etre publie",
                "Un dossier peut etre clos sans advisory : correctif verifie sans interet "
                "public, infrastructure trop sensible pour etre decrite, demande motivee "
                "de l'organisation. La decision appartient a la coordination nationale et "
                "se prend dossier par dossier - elle laisse une trace, comme le reste.",
                couleur=NAVY_CLAIR,
                fond=colors.HexColor("#eef4fa"),
            ),
        ],
    )
    return blocs


def chapitre_9():
    blocs = chapitre(9, "Cas particuliers et issues alternatives", "Ce qui sort du rail")
    blocs += [
        p("9.1 Le declarant ne repond plus", "h2"),
        p(
            "Un dossier en <b>Informations demandees</b> attend une reponse qui ne vient "
            "pas toujours. L'echeance de triage continue de courir et le dossier remonte "
            "dans la file a mesure qu'il vieillit. Deux issues : relancer par la "
            "messagerie, ou trancher sur les seuls elements disponibles - le plus "
            "souvent <b>Rejete</b>, faute de demonstration. Dans les deux cas, le motif "
            "est ecrit dans le commentaire de transition : c'est lui que relira le "
            "collegue qui reprendra le dossier."
        ),
        espace(4),
        p("9.2 Doublon : ce que le declarant apprend, et ce qu'il n'apprend pas", "h2"),
        p(
            "Marquer un doublon rattache le dossier a l'original et le clot. Le declarant "
            "est informe que son rapport est un doublon - <b>rien de plus</b>. Ni la "
            "reference du dossier d'origine, ni son contenu, ni l'organisation concernee "
            "ne lui sont reveles : ce serait lui apprendre l'existence d'une "
            "vulnerabilite non corrigee qu'il n'a pas decouverte. Seule la coordination "
            "nationale voit le lien entre les deux dossiers."
        ),
        espace(4),
        p("9.3 Rapport chiffre PGP", "h2"),
        p(
            "Un declarant peut coller un bloc PGP chiffre a la place du contenu sensible. "
            "La plateforme verifie qu'il s'agit bien d'un message chiffre, le stocke tel "
            "quel et signale le dossier comme chiffre. <b>Aucune cle privee n'est "
            "detenue par la plateforme</b> : le dechiffrement se fait hors ligne, par "
            "l'equipe destinataire, avec sa propre cle. Le traitement suit son cours "
            "normalement pour tout le reste."
        ),
        espace(4),
        p("9.4 Le declarant est anonyme et injoignable", "h2"),
        p(
            "Le dossier vit sa vie complete - triage, correction, publication - mais "
            "aucune notification ne part. En pratique : pas de demande d'information "
            "possible, donc un rapport incomplet finira rejete ; pas de "
            "contre-verification du correctif par le declarant ; credit public mentionne "
            "comme anonyme. C'est le cout de l'anonymat total, et il est assume."
        ),
        espace(4),
        p("9.5 Pieces jointes refusees", "h2"),
        p(
            "Les pieces jointes sont controlees a trois niveaux : taille, extension, et "
            "<b>signature binaire</b> du contenu. Un executable renomme en .png est "
            "refuse - c'est sa signature qui le trahit, pas son nom. Chaque fichier "
            "accepte recoit une empreinte SHA-256, et chaque telechargement est "
            "journalise : ces fichiers sont des preuves de vulnerabilites non corrigees."
        ),
        espace(4),
        p("9.6 Un signalement qui ne vise aucune organisation referencee", "h2"),
        p(
            "Le declarant peut nommer librement une entite absente de l'annuaire. Le "
            "dossier reste alors visible de la seule equipe nationale : personne, cote "
            "organisation, ne peut y acceder. C'est au triage de rattacher le dossier a "
            "l'organisation reelle - ou de la faire creer - faute de quoi la coordination "
            "de l'etape 5 n'a pas d'interlocuteur."
        ),
        espace(4),
        p("9.7 Reprendre un dossier clos", "h2"),
        p(
            "Les etats <b>Clos</b>, <b>Rejete</b>, <b>Doublon</b>, <b>Hors perimetre</b> "
            "et <b>Non applicable</b> sont terminaux : la machine a etats n'en laisse "
            "sortir aucune transition. Si un element nouveau apparait - un rejet errone, "
            "une regression du correctif - la marche a suivre est d'ouvrir un nouveau "
            "dossier et d'y citer l'ancien. L'historique du premier reste intact, ce qui "
            "est precisement l'interet de ne pas le rouvrir."
        ),
    ]
    return blocs


def chapitre_10():
    blocs = chapitre(10, "Delais, priorites et ecrans de pilotage", "Tenir la charge")
    blocs += [
        p("10.1 Les cinq echeances et leur cycle", "h2"),
        p(
            "Chaque echeance passe par les memes etats : <b>En cours</b>, puis "
            "<b>Echeance proche</b> a 80 % du delai, puis <b>Respectee</b> si l'action "
            "attendue survient, <b>Depassee</b> sinon. La cloture ou la publication "
            "<b>annule</b> les echeances restantes."
        ),
        espace(2),
        tableau(
            ["Echeance", "Armee par", "Soldee par", "Qui doit agir"],
            [
                [
                    "Accuse de reception<br/><b>72 h</b>",
                    "Le depot du signalement",
                    "Passage en Recu ou Accuse de reception",
                    "Agent de triage, analyste",
                ],
                [
                    "Premier triage<br/><b>5 jours</b>",
                    "Le depot du signalement",
                    "Entree en triage ou decision de triage",
                    "Agent de triage, analyste",
                ],
                [
                    "Reponse de l'organisation<br/><b>7 jours</b>",
                    "Le contact de l'organisation",
                    "Accuse de reception de l'organisation",
                    "DSI, responsable d'organisation",
                ],
                [
                    "Remediation<br/><b>30 / 60 / 90 jours</b>",
                    "La validation, ou l'entree en remediation",
                    "Correctif disponible ou verifie",
                    "DSI, responsable d'organisation",
                ],
                [
                    "Divulgation<br/><b>date fixee</b>",
                    "La planification de la divulgation",
                    "La publication de l'advisory",
                    "Analyste, coordinateur national",
                ],
            ],
            [40 * mm, 40 * mm, 44 * mm, L - 124 * mm],
        ),
        espace(6),
        p("10.2 Le score de priorite", "h2"),
        p(
            "Chaque dossier ouvert porte un score de 0 a 100 qui ordonne la file de "
            "travail. Il se recalcule a chaque changement d'etat et, chaque nuit, pour "
            "tous les dossiers ouverts."
        ),
        espace(2),
        tableau(
            ["Composante", "Apport au score"],
            [
                [
                    "Severite retenue",
                    "Critique 80, Elevee 60, Moyenne 35, Faible 15, Informative 5",
                ],
                [
                    "Secteur de l'organisation",
                    "+5 pour la defense et le gouvernement",
                ],
                [
                    "Anciennete",
                    "+1 par semaine ecoulee, plafonne a +10",
                ],
                [
                    "Echeance depassee",
                    "+10 des le premier depassement",
                ],
            ],
            [50 * mm, L - 50 * mm],
        ),
        espace(3),
        p(
            "Un dossier moyen qui traine finit donc par depasser un dossier eleve tout "
            "juste arrive : c'est voulu. L'anciennete et le retard sont des risques, au "
            "meme titre que la severite.",
            "petit",
        ),
        espace(6),
        p("10.3 Ou travailler, selon le role", "h2"),
        tableau(
            ["Ecran", "Adresse", "Pour qui", "Usage"],
            [
                [
                    "<b>File des dossiers</b>",
                    "/cases/",
                    "Equipe nationale, organisation",
                    "Liste filtrable par statut, severite, organisation, texte. Triee "
                    "par priorite.",
                ],
                [
                    "<b>Tableau Kanban</b>",
                    "/cases/kanban/",
                    "Equipe nationale, organisation",
                    "Les sept colonnes du workflow : Soumis, Triage, Valide, "
                    "Remediation, Verification, Divulgation, Clos. Vue de charge.",
                ],
                [
                    "<b>Fiche d'un dossier</b>",
                    "/cases/EVDP-.../",
                    "Participants du dossier",
                    "Rapport, messagerie, pieces jointes, chronologie, echeances, "
                    "participants, et les actions autorisees par le role.",
                ],
                [
                    "<b>Tableau de bord CSIRT</b>",
                    "/dashboard/csirt/",
                    "Triage, analyste, coordinateur, auditeur",
                    "Volumes, repartition par severite, par secteur, par type, top CWE, "
                    "dossiers en retard, delai moyen de correction.",
                ],
                [
                    "<b>Tableau de bord national</b>",
                    "/dashboard/national/",
                    "Coordinateur, auditeur",
                    "Posture agregee : aucune information identifiant une infrastructure "
                    "sensible.",
                ],
                [
                    "<b>Espace organisation</b>",
                    "/dashboard/organization/",
                    "DSI, responsable d'organisation",
                    "Les seules vulnerabilites de l'entite, ses retards, ses programmes, "
                    "ses advisories.",
                ],
                [
                    "<b>Espace chercheur</b>",
                    "/dashboard/researcher/",
                    "Declarants inscrits",
                    "Ses dossiers, ses recompenses, sa reputation, les programmes " "ouverts.",
                ],
                [
                    "<b>Recherche globale</b>",
                    "/dashboard/search/",
                    "Equipe nationale, organisation",
                    "Recherche transverse dans le perimetre visible.",
                ],
                [
                    "<b>Recompenses</b>",
                    "/bounties/",
                    "Selon le perimetre visible",
                    "Suivi des propositions, revues, approbations et versements.",
                ],
                [
                    "<b>Redaction d'advisories</b>",
                    "/advisories/manage/",
                    "Analyste, coordinateur",
                    "Brouillons, relectures, publications, retraits.",
                ],
                [
                    "<b>Journal d'audit</b>",
                    "/audit/",
                    "Coordinateur, auditeur",
                    "Toutes les actions, y compris les refus.",
                ],
            ],
            [32 * mm, 36 * mm, 30 * mm, L - 98 * mm],
        ),
        espace(4),
        p(
            "Le menu lateral se deduit du role : il n'affiche que ce que le compte peut "
            "reellement ouvrir. Un menu qui annoncerait une page interdite apprendrait au "
            "lecteur a se mefier de ce qu'il lit.",
            "petit",
        ),
        espace(6),
        p("10.4 Exports", "h2"),
        p(
            "Les exports reprennent exactement le perimetre visible de celui qui les "
            "demande, et sont journalises : <b>CSV</b> et <b>Excel</b> de la liste des "
            "dossiers, <b>PDF</b> d'un dossier complet, <b>CSV</b> des comptes non "
            "verifies sur le point de perdre l'acces aux programmes Bug Bounty. Capacite "
            "requise : EXPORT_DATA."
        ),
    ]
    return blocs


def chapitre_11():
    blocs = chapitre(11, "Echanger sur un dossier", "Messagerie, avis, fichiers")
    blocs += [
        p("11.1 Les trois niveaux de confidentialite", "h2"),
        p(
            "Tous les messages d'un dossier s'ecrivent au meme endroit. Ce qui change, "
            "c'est le niveau choisi avant l'envoi - et donc qui lira."
        ),
        espace(2),
        tableau(
            ["Niveau", "Lu par", "Usage", "Qui peut l'employer"],
            [
                [
                    "<b>Participants</b>",
                    "Declarant, organisation affectee, equipe nationale",
                    "Tout ce qui s'adresse au declarant ou a l'entite : demande "
                    "d'information, contact initial, suivi de correction, verification.",
                    "Tous les participants",
                ],
                [
                    "<b>Interne CSIRT</b>",
                    "Equipe nationale uniquement",
                    "Analyse entre collegues, hypotheses, coordination interne.",
                    "Capacite POST_INTERNAL_MESSAGE",
                ],
                [
                    "<b>Restreint</b>",
                    "<b>Coordination nationale uniquement</b>",
                    "Elements sensibles : liens entre dossiers, contexte politique, "
                    "arbitrages.",
                    "Coordinateur national, administrateur",
                ],
            ],
            [26 * mm, 40 * mm, L - 106 * mm, 40 * mm],
        ),
        espace(3),
        encadre(
            "Le declarant lit les messages Participants",
            "C'est l'erreur la plus courante et la plus couteuse : une analyse interne "
            "postee au niveau Participants est lue par le declarant et par "
            "l'organisation, et rien ne permet de la reprendre. Le niveau se verifie "
            "avant l'envoi. Un chercheur ou une DSI, eux, n'ont acces qu'au niveau "
            "Participants : ils ne peuvent pas se tromper.",
            couleur=ROUGE,
            fond=colors.HexColor("#fbe9e7"),
        ),
        espace(6),
        p("11.2 Qui est prevenu, et quand", "h2"),
        tableau(
            ["Evenement", "Destinataire", "Canal"],
            [
                [
                    "Nouveau signalement",
                    "Agents de triage, analystes CSIRT, coordinateurs",
                    "Notification interne et courriel",
                ],
                [
                    "Accuse de reception, validation, rejet, doublon, demande "
                    "d'information",
                    "Le declarant",
                    "Notification et courriel s'il a un compte ; courriel seul s'il a "
                    "laisse une adresse",
                ],
                [
                    "Tout autre changement de statut",
                    "Le declarant et l'equipe du dossier, sauf l'auteur de l'action",
                    "Notification et courriel",
                ],
                [
                    "Nouveau message, nouvelle piece jointe",
                    "Les participants du dossier, sauf l'auteur",
                    "Notification et courriel",
                ],
                [
                    "Assignation",
                    "L'analyste designe",
                    "Notification et courriel",
                ],
                [
                    "Echeance proche, echeance depassee",
                    "L'equipe du dossier",
                    "Notification et courriel",
                ],
                [
                    "Divulgation prevue sous 7 jours",
                    "L'equipe du dossier",
                    "Notification et courriel",
                ],
                [
                    "Recompense proposee, approuvee, rejetee, payee",
                    "Le chercheur",
                    "Notification et courriel",
                ],
                [
                    "Advisory publie",
                    "Le chercheur, avec le lien public",
                    "Notification et courriel",
                ],
            ],
            [56 * mm, 50 * mm, L - 106 * mm],
        ),
        espace(6),
        p("11.3 Pieces jointes", "h2"),
    ]
    blocs += puces(
        [
            "Cinq fichiers au maximum a la soumission ; d'autres peuvent etre ajoutes "
            "ensuite depuis la fiche du dossier.",
            "Extensions autorisees limitees, extensions dangereuses interdites, taille "
            "plafonnee, <b>signature binaire verifiee</b> : un executable deguise est "
            "refuse.",
            "Chaque fichier porte une empreinte SHA-256, son auteur et sa date ; chaque "
            "telechargement est journalise.",
            "Ces fichiers contiennent des preuves de vulnerabilites <b>non corrigees</b> : "
            "ils ne sortent pas de la plateforme, et les sauvegardes qui les contiennent "
            "sont chiffrees.",
        ]
    )
    return blocs


def chapitre_12():
    blocs = chapitre(12, "Ce que voit le declarant", "Vue cote signalant")
    blocs += [
        p(
            "Un traitement rigoureux cote CSIRT ne vaut que si le declarant comprend ou "
            "en est son signalement. Voici exactement ce qui lui parvient, selon son "
            "profil, a chaque etape."
        ),
        espace(3),
        tableau(
            [
                "Etape",
                "Citoyen anonyme",
                "Citoyen avec adresse",
                "Chercheur inscrit / Bug Bounty",
            ],
            [
                [
                    "<b>Depot</b>",
                    "Reference affichee a l'ecran",
                    "Reference affichee, plus un courriel",
                    "Reference, redirection vers le dossier, notification",
                ],
                [
                    "<b>Accuse de reception</b>",
                    "Rien",
                    "Courriel",
                    "Notification, courriel, statut visible",
                ],
                [
                    "<b>Demande d'information</b>",
                    "Impossible",
                    "Courriel, sans possibilite de repondre dans le dossier",
                    "Notification, et reponse par la messagerie",
                ],
                [
                    "<b>Validation ou rejet</b>",
                    "Rien",
                    "Courriel",
                    "Notification, motif visible, points de reputation",
                ],
                [
                    "<b>Correction en cours</b>",
                    "Rien",
                    "Courriel a chaque changement de statut",
                    "Chronologie, echeances et messages en direct",
                ],
                [
                    "<b>Verification</b>",
                    "Impossible",
                    "Non sollicite",
                    "Sollicite par message pour confirmer le correctif",
                ],
                [
                    "<b>Publication</b>",
                    "Advisory public, credit anonyme",
                    "Courriel, credit selon son choix",
                    "Notification avec le lien, credit selon son mode d'identite",
                ],
                [
                    "<b>Recompense</b>",
                    "Sans objet",
                    "Sans objet",
                    "Bug Bounty : suivi du montant propose, approuve, verse",
                ],
            ],
            [30 * mm, 32 * mm, 44 * mm, L - 106 * mm],
        ),
        espace(6),
        p("Ce que le declarant ne voit jamais", "h2"),
    ]
    blocs += puces(
        [
            "Les messages <b>internes</b> et <b>restreints</b>, meme sur son propre "
            "dossier.",
            "Le dossier d'origine lorsqu'on lui repond <b>doublon</b>.",
            "Qui a proposé, discuté ou signé sa récompense : il en voit le montant "
            "et l'état d'avancement, jamais la délibération.",
            "Les dossiers des autres, y compris ceux qui visent la meme organisation.",
            "Le journal d'audit, les tableaux de bord et les exports.",
        ]
    )
    blocs += [
        espace(4),
        p("Sa reputation, s'il est inscrit", "h2"),
        p(
            "La reputation derive exclusivement d'evenements produits par le traitement : "
            "elle n'est jamais saisie a la main, ni modifiable par le chercheur. Un "
            "rapport valide rapporte les points de base ; une severite elevee ou "
            "critique ouvre un bonus ; un doublon ne rapporte rien ; un comportement "
            "abusif retire des points. Le bareme est un parametre de deploiement, pas "
            "une constante du code.",
        ),
    ]
    return blocs


def _scenario(titre, intro, lignes):
    return [
        p(titre, "h2"),
        p(intro),
        espace(2),
        tableau(
            ["Jour", "Qui", "Ce qui se passe", "Etat du dossier"],
            lignes,
            [14 * mm, 34 * mm, L - 92 * mm, 44 * mm],
        ),
        espace(8),
    ]


def chapitre_13():
    blocs = chapitre(13, "Trois parcours de bout en bout", "Mise en situation")
    blocs += [
        p(
            "Les memes regles, vues du debut a la fin, sur trois dossiers typiques. Les "
            "jours sont indicatifs : ils illustrent des delais tenus."
        ),
        espace(4),
    ]

    blocs += _scenario(
        "13.1 Un citoyen signale un site ministeriel",
        "Un agent d'un ministere constate que le portail de son service affiche les "
        "dossiers d'autres usagers en changeant un numero dans l'adresse. Il n'a pas de "
        "compte et prefere ne pas en creer, mais laisse une adresse de contact.",
        [
            [
                "J+0",
                "Le citoyen",
                "Depose sur /report/ : description, adresse concernee, capture d'ecran. "
                "Laisse une adresse de contact, accepte la politique.",
                "SUBMITTED",
            ],
            [
                "J+0",
                "Plateforme",
                "Ouvre EVDP-2026-000412, arme les echeances 72 h et 5 jours, previent "
                "l'equipe de triage, envoie l'accuse de depot.",
                "SUBMITTED",
            ],
            [
                "J+1",
                "Agent de triage",
                "Lit le rapport, le juge exploitable, accuse reception.",
                "RECEIVED puis ACKNOWLEDGED",
            ],
            [
                "J+2",
                "Analyste CSIRT",
                "S'assigne le dossier, reproduit la faille, qualifie : severite "
                "<b>Elevee</b>, vecteur CVSS, CWE-639, rattache le dossier au ministere.",
                "TRIAGE",
            ],
            [
                "J+2",
                "Analyste CSIRT",
                "Valide. La date de divulgation est calculee a J+92 et l'echeance de "
                "correction de 30 jours s'arme.",
                "VALIDATED",
            ],
            [
                "J+3",
                "Analyste CSIRT",
                "Contacte le ministere : la DSI et le contact securite sont deja "
                "participants du dossier.",
                "VENDOR_CONTACTED",
            ],
            [
                "J+5",
                "DSI du ministere",
                "Accuse reception, annonce un correctif sous quinze jours.",
                "VENDOR_ACKNOWLEDGED",
            ],
            [
                "J+18",
                "DSI du ministere",
                "Deploie le controle d'acces manquant et declare le correctif.",
                "REMEDIATION puis FIX_AVAILABLE",
            ],
            [
                "J+20",
                "Analyste CSIRT",
                "Verifie : la manipulation ne fonctionne plus.",
                "VERIFICATION puis FIX_VERIFIED",
            ],
            [
                "J+21",
                "Coordinateur national",
                "Juge qu'un advisory public n'apporterait rien - defaut de configuration "
                "propre a une application interne - et clot le dossier.",
                "CLOSED",
            ],
            [
                "J+21",
                "Le citoyen",
                "Recoit le courriel de cloture. Il aura ete informe a chaque etape, sans "
                "jamais creer de compte.",
                "-",
            ],
        ],
    )

    blocs.append(PageBreak())

    blocs += _scenario(
        "13.2 Un chercheur inscrit, dossier publie avec CVE",
        "Une chercheuse inscrite, identite publique, decouvre une injection SQL non "
        "authentifiee sur un teleservice d'un etablissement public. Elle demande un CVE "
        "et souhaite etre creditee.",
        [
            [
                "J+0",
                "La chercheuse",
                "Depose depuis son compte, joint une preuve de concept, coche la demande "
                "de CVE et le credit public.",
                "SUBMITTED",
            ],
            [
                "J+0",
                "Plateforme",
                "Ouvre le dossier et la redirige dessus : elle y suivra tout.",
                "SUBMITTED",
            ],
            [
                "J+1",
                "Analyste CSIRT",
                "Accuse reception, s'assigne le dossier.",
                "ACKNOWLEDGED",
            ],
            [
                "J+2",
                "Analyste CSIRT",
                "Demande une precision sur l'environnement de test.",
                "NEEDS_INFORMATION",
            ],
            [
                "J+2",
                "La chercheuse",
                "Repond dans la messagerie du dossier, au niveau Participants.",
                "NEEDS_INFORMATION",
            ],
            [
                "J+3",
                "Analyste CSIRT",
                "Reprend le triage : severite <b>Critique</b>, CVSS 9.8, CWE-89. Valide. "
                "La chercheuse recoit ses points de reputation, majores.",
                "TRIAGE puis VALIDATED",
            ],
            [
                "J+3",
                "Analyste CSIRT",
                "Contacte l'etablissement. Ouvre un fil <b>interne</b> pour l'analyse "
                "d'impact : la chercheuse ne le voit pas.",
                "VENDOR_CONTACTED",
            ],
            [
                "J+6",
                "Responsable d'organisation",
                "Accuse reception et engage la correction.",
                "VENDOR_ACKNOWLEDGED puis REMEDIATION",
            ],
            [
                "J+24",
                "Plateforme",
                "Alerte <b>echeance proche</b> a 80 % des 30 jours : l'equipe et l'entite "
                "sont prevenues.",
                "REMEDIATION",
            ],
            [
                "J+27",
                "DSI",
                "Livre le correctif en production.",
                "FIX_AVAILABLE",
            ],
            [
                "J+29",
                "La chercheuse",
                "Sollicitee par message, confirme que l'injection n'est plus exploitable.",
                "VERIFICATION",
            ],
            [
                "J+29",
                "Analyste CSIRT",
                "Entérine la verification, associe le CVE obtenu, planifie la divulgation "
                "a J+45.",
                "FIX_VERIFIED puis DISCLOSURE_SCHEDULED",
            ],
            [
                "J+31",
                "Analyste CSIRT",
                "Redige l'advisory depuis le dossier : brouillon assaini, sans preuve de "
                "concept ni etapes de reproduction. Passe en relecture.",
                "DISCLOSURE_SCHEDULED",
            ],
            [
                "J+38",
                "Coordinateur national",
                "Relit, approuve, verifie le credit et la chronologie publique.",
                "DISCLOSURE_SCHEDULED",
            ],
            [
                "J+45",
                "Coordinateur national",
                "Publie l'advisory. La chercheuse recoit le lien ; son nom y figure.",
                "PUBLISHED",
            ],
            [
                "J+46",
                "Analyste CSIRT",
                "Clot le dossier ; les echeances restantes sont annulees.",
                "CLOSED",
            ],
        ],
    )

    blocs.append(PageBreak())

    blocs += _scenario(
        "13.3 Un chercheur Bug Bounty recompense",
        "Un chercheur Bug Bounty, compte verifie, travaille sur un programme ouvert par "
        "une entreprise publique. Il trouve un contournement d'authentification sur une "
        "API listee au perimetre.",
        [
            [
                "J+0",
                "Le chercheur",
                "Lit le perimetre, les regles et la grille, puis depose depuis la fiche "
                "du programme. Le programme est pre-selectionne.",
                "SUBMITTED",
            ],
            [
                "J+0",
                "Plateforme",
                "Verifie compte et adresse verifiee, ouvre le dossier sur le "
                "<b>workflow Bug Bounty</b>.",
                "SUBMITTED",
            ],
            [
                "J+1",
                "Agent de triage",
                "Accuse reception.",
                "ACKNOWLEDGED",
            ],
            [
                "J+2",
                "Analyste CSIRT",
                "Qualifie : severite <b>Critique</b>, et retient l'<b>actif</b> API de "
                "production - qui a sa propre grille de recompense. Valide.",
                "TRIAGE puis VALIDATED",
            ],
            [
                "J+2",
                "Analyste CSIRT",
                "Attribue la severite definitive au titre du programme.",
                "SEVERITY_ASSIGNED",
            ],
            [
                "J+3",
                "Analyste CSIRT",
                "Propose une recompense : la plateforme suggere la borne haute du palier "
                "de l'actif. Le chercheur est notifie de la proposition.",
                "BOUNTY_REVIEW",
            ],
            [
                "J+4",
                "Responsable d'organisation",
                "Donne un avis favorable et confirme l'impact metier.",
                "BOUNTY_REVIEW",
            ],
            [
                "J+5",
                "<b>Coordinateur national</b>",
                "Approuve le montant - l'analyste qui l'a propose n'en a pas le droit - "
                "et signe la decision.",
                "REWARD_APPROVED",
            ],
            [
                "J+5",
                "Analyste CSIRT",
                "Bascule le dossier en correction ; la recompense suit son cours "
                "separement.",
                "REMEDIATION",
            ],
            [
                "J+12",
                "Service financier",
                "Verse la recompense hors plateforme.",
                "REMEDIATION",
            ],
            [
                "J+12",
                "Coordinateur national",
                "Enregistre le versement : montant, moyen, reference. Le chercheur est "
                "notifie et son cumul percu est mis a jour.",
                "REMEDIATION",
            ],
            [
                "J+19",
                "DSI",
                "Corrige et declare le correctif.",
                "FIX_AVAILABLE",
            ],
            [
                "J+21",
                "Analyste CSIRT",
                "Fait verifier par le chercheur, puis enterine.",
                "VERIFICATION puis FIX_VERIFIED",
            ],
            [
                "J+60",
                "Coordinateur national",
                "Publie l'advisory a la date convenue, puis le dossier est clos.",
                "PUBLISHED puis CLOSED",
            ],
        ],
    )
    return blocs


def chapitre_14():
    blocs = chapitre(14, "Tracabilite et controle", "Ce qui reste ecrit")
    blocs += [
        p(
            "Chaque acte du traitement laisse trois traces distinctes, qui ne servent pas "
            "au meme usage."
        ),
        espace(2),
        tableau(
            ["Trace", "Contenu", "Qui la lit"],
            [
                [
                    "<b>Chronologie du dossier</b>",
                    "Les jalons metiers : rapport recu, accuse de reception, validation, "
                    "organisation contactee, correctif fourni et verifie, divulgation, "
                    "publication, cloture. Certains sont marques publics et alimentent "
                    "l'advisory.",
                    "Tous les participants",
                ],
                [
                    "<b>Historique des statuts</b>",
                    "Chaque transition : etat de depart, etat d'arrivee, auteur, date, "
                    "commentaire.",
                    "Les participants du dossier",
                ],
                [
                    "<b>Journal d'audit</b>",
                    "Connexions et echecs, consultations de dossier, modifications, "
                    "messages, pieces jointes televersees et telechargees, decisions de "
                    "recompense, publications, exports - et les <b>refus</b>.",
                    "Coordinateur national, auditeur",
                ],
            ],
            [40 * mm, L - 80 * mm, 40 * mm],
        ),
        espace(5),
        encadre(
            "Un refus laisse une trace, meme quand l'action echoue",
            "Lorsqu'une transition interdite est tentee, le controle a lieu <b>hors "
            "transaction</b> : l'ecriture de la trace ne peut pas etre annulee par le "
            "rejet de l'action. Un dossier ou l'on voit dix transitions refusees en cinq "
            "minutes raconte quelque chose - encore faut-il que la trace survive.",
        ),
        espace(6),
        p("Cinq regles que la plateforme fait respecter d'elle-meme", "h2"),
    ]
    blocs += puces(
        [
            "<b>Isolation.</b> Chaque requete de dossier est filtree par le perimetre du "
            "compte : un declarant ne voit que ses dossiers, une organisation que les "
            "siens. Le filtre est applique au niveau des donnees, pas de l'affichage.",
            "<b>Dossier introuvable plutot qu'acces refuse.</b> Un dossier hors "
            "perimetre repond <b>introuvable</b> : confirmer son existence serait deja "
            "une information.",
            "<b>Lecture seule reelle.</b> Le role d'auditeur est refuse a l'ecriture par "
            "le serveur, action par action.",
            "<b>Le rapport d'origine n'est jamais modifie.</b> La qualification vit sur "
            "le dossier ; ce que le declarant a ecrit reste tel quel.",
            "<b>Aucune publication implicite.</b> Aucun champ du rapport ne devient public "
            "par defaut : l'advisory est une redaction distincte, relue et approuvee.",
        ]
    )
    return blocs


def annexes():
    blocs = chapitre("A", "Les etats du dossier", "Annexe")
    blocs += [
        p(
            "Vingt-quatre etats, dont trois propres au Bug Bounty. La colonne "
            "<b>Autorisation</b> indique la capacite exigee pour y conduire un dossier, "
            "au-dela de CHANGE_CASE_STATUS.",
            "petit",
        ),
        espace(3),
        tableau(
            ["Etat", "Signification", "Autorisation"],
            [
                ["DRAFT", "Brouillon non soumis", "-"],
                ["SUBMITTED", "Rapport soumis, en attente de prise en charge", "-"],
                ["RECEIVED", "Reception enregistree par l'equipe", "CHANGE_CASE_STATUS"],
                [
                    "ACKNOWLEDGED",
                    "Accuse de reception envoye au declarant",
                    "CHANGE_CASE_STATUS",
                ],
                ["TRIAGE", "Qualification technique en cours", "CHANGE_CASE_STATUS"],
                [
                    "NEEDS_INFORMATION",
                    "Informations complementaires demandees",
                    "CHANGE_CASE_STATUS",
                ],
                ["VALIDATED", "Vulnerabilite confirmee", "<b>TRIAGE_CASE</b>"],
                [
                    "SEVERITY_ASSIGNED",
                    "Severite attribuee (Bug Bounty)",
                    "<b>SET_SEVERITY</b>",
                ],
                ["BOUNTY_REVIEW", "Revue de recompense (Bug Bounty)", "<b>PROPOSE_BOUNTY</b>"],
                [
                    "REWARD_APPROVED",
                    "Recompense approuvee (Bug Bounty)",
                    "<b>APPROVE_BOUNTY</b>",
                ],
                [
                    "DUPLICATE",
                    "Doublon d'un dossier existant - terminal",
                    "<b>TRIAGE_CASE</b>",
                ],
                ["REJECTED", "Non retenue - terminal", "<b>TRIAGE_CASE</b>"],
                [
                    "OUT_OF_SCOPE",
                    "Hors perimetre du programme - terminal",
                    "<b>TRIAGE_CASE</b>",
                ],
                ["NOT_APPLICABLE", "Sans objet - terminal", "<b>TRIAGE_CASE</b>"],
                [
                    "INFORMATIVE",
                    "Information utile, sans vulnerabilite exploitable",
                    "<b>TRIAGE_CASE</b>",
                ],
                ["IN_PROGRESS", "Prise en charge engagee", "CHANGE_CASE_STATUS"],
                ["VENDOR_CONTACTED", "Organisation affectee contactee", "CHANGE_CASE_STATUS"],
                [
                    "VENDOR_ACKNOWLEDGED",
                    "L'organisation a accuse reception",
                    "CHANGE_CASE_STATUS",
                ],
                ["REMEDIATION", "Correction en cours", "CHANGE_CASE_STATUS"],
                ["FIX_AVAILABLE", "Correctif disponible", "CHANGE_CASE_STATUS"],
                ["VERIFICATION", "Verification du correctif", "CHANGE_CASE_STATUS"],
                ["FIX_VERIFIED", "Correctif verifie", "CHANGE_CASE_STATUS"],
                ["DISCLOSURE_SCHEDULED", "Date de divulgation fixee", "CHANGE_CASE_STATUS"],
                ["PUBLISHED", "Advisory publie", "<b>PUBLISH_ADVISORY</b>"],
                ["CLOSED", "Dossier clos - terminal", "CHANGE_CASE_STATUS"],
            ],
            [42 * mm, L - 84 * mm, 42 * mm],
        ),
    ]

    blocs += chapitre("B", "Ce qui se regle sans toucher au code", "Annexe")
    blocs += [
        p(
            "Les valeurs citees dans ce manuel sont celles livrees par defaut. Toutes se "
            "modifient par l'administration ou par la configuration du deploiement."
        ),
        espace(3),
        tableau(
            ["Reglage", "Où", "Effet"],
            [
                [
                    "Delais d'accuse de reception, de triage, de reponse de "
                    "l'organisation, de correction",
                    "Administration, politiques de delai",
                    "S'appliquent aux nouveaux dossiers ; un programme peut avoir sa "
                    "propre politique.",
                ],
                [
                    "Seuil d'alerte (80 %)",
                    "Politique de delai",
                    "Determine le moment de l'avertissement avant depassement.",
                ],
                [
                    "Delai de divulgation (90 jours)",
                    "Fiche du programme",
                    "Sert au calcul de la date de divulgation a la validation.",
                ],
                [
                    "Matrice de recompense",
                    "Fiche du programme",
                    "Paliers par severite, affinables par actif ; devise et budget.",
                ],
                [
                    "Bareme de reputation",
                    "Configuration du deploiement",
                    "Points de validation, bonus de severite, penalite d'abus.",
                ],
                [
                    "Exigence d'adresse verifiee et sursis",
                    "Fiche du programme, configuration",
                    "Conditionne la participation aux programmes ; le sursis ne vise que "
                    "les comptes anterieurs a la bascule.",
                ],
                [
                    "Politique de divulgation publique",
                    "Administration, parametres du site",
                    "Texte affiche sur /disclosure-policy/ et rappele au depot.",
                ],
                [
                    "Extensions et taille des pieces jointes",
                    "Configuration du deploiement",
                    "Liste autorisee, liste interdite, plafond.",
                ],
            ],
            [48 * mm, 40 * mm, L - 88 * mm],
        ),
        espace(8),
        p("Pour aller plus loin", "h2"),
        p(
            "Ce manuel decrit le processus. La documentation technique du depot le "
            "complete : <b>docs/cvd-workflow.md</b> pour la machine a etats, "
            "<b>docs/bug-bounty.md</b> pour les programmes et les recompenses, "
            "<b>docs/administration.md</b> pour l'exploitation courante, "
            "<b>docs/security.md</b> pour le modele de menaces, <b>docs/api.md</b> pour "
            "l'interface programmatique.",
            "petit",
        ),
    ]
    return blocs


# --------------------------------------------------------------------------
# Assemblage
# --------------------------------------------------------------------------
def construire(chemin=SORTIE):
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)

    histoire = [Spacer(1, 1)]  # la couverture est peinte par le gabarit
    histoire += sommaire()
    for fabrique in (
        chapitre_1,
        chapitre_2,
        chapitre_3,
        chapitre_4,
        chapitre_5,
        chapitre_6,
        chapitre_7,
        chapitre_8,
        chapitre_9,
        chapitre_10,
        chapitre_11,
        chapitre_12,
        chapitre_13,
        chapitre_14,
        annexes,
    ):
        histoire += fabrique()

    document = Document(chemin)
    document.multiBuild(histoire, canvasmaker=_fabrique_canevas())
    return chemin


def main():
    sortie = Path(sys.argv[1]) if len(sys.argv) > 1 else SORTIE
    chemin = construire(sortie)
    taille = chemin.stat().st_size / 1024
    print(f"Manuel généré : {chemin} ({taille:.0f} Ko)")


# ==========================================================================
# Accentuation
# ==========================================================================
# Le corps du manuel est redige sans accents, comme le reste des sources
# Python du depot. Le lecteur, lui, lit du francais : les accents sont
# reposes ici, au moment de fabriquer chaque Paragraph. Un seul passage,
# applique aux seules chaines destinees a l'oeil - jamais aux noms de style
# ni aux identifiants d'etat, qui sont en majuscules.
#
# Trois couches, dans cet ordre :
#   1. les tournures ou un mot court change de sens (a/a, ou/ou, des/des) ;
#   2. les participes passes, que leur forme nue confond avec un present ;
#   3. le lexique, ou chaque forme n'a qu'une lecture possible.


#: Tournures protegees : "a" y est le verbe avoir, pas la preposition.
_VERBE_A = [
    ("a ete", "a été"),
    ("a accuse", "a accusé"),
    ("a laisse", "a laissé"),
    ("il a un compte", "il a un compte"),
    ("a pu", "a pu"),
    ("a propose", "a proposé"),
    ("a clos", "a clos"),
    ("a le droit", "a le droit"),
    ("a ecrit", "a écrit"),
    ("a rattache", "a rattaché"),
    ("a sa propre", "a sa propre"),
    ("n'en a pas", "n'en a pas"),
    ("y a acces", "y a accès"),
    ("a lieu", "a lieu"),
    ("a deja", "a déjà"),
    ("a bien ete", "a bien été"),
    ("a evolue", "a évolué"),
    ("a repondu", "a répondu"),
]

#: Tournures a reecrire en bloc, avant tout traitement mot a mot.
_TOURNURES = [
    (r"\bjusqu'a\b", "jusqu'à"),
    (r"\bqu'a la fin\b", "qu'à la fin"),
    (r"\bau-dela\b", "au-delà"),
    (r"\bD'ou\b", "D'où"),
    (r"\bmoment ou\b", "moment où"),
    (r"\bceux ou ils\b", "ceux où ils"),
    (r"\bdossier ou l'on\b", "dossier où l'on"),
    (r"\bcomprend ou en est\b", "comprend où en est"),
    (r"\bdepuis quel ecran\b", "depuis quel écran"),
    (r"\bdes l'", "dès l'"),
    (r"\bdes la\b", "dès la"),
    (r"\bdes le premier\b", "dès le premier"),
    (r"\bdes maintenant\b", "dès maintenant"),
    (r"\bdes 80\b", "dès 80"),
    (r"\bDes l'", "Dès l'"),
    (r"\bentretemps\b", "entre-temps"),
    (r"\bpre-selectionne\b", "pré-sélectionné"),
    (r"\baccuse de reception\b", "accusé de réception"),
    (r"\bAccuse de reception\b", "Accusé de réception"),
    (r"\bL'accuse de reception\b", "L'accusé de réception"),
    (r"\baccuse de depot\b", "accusé de dépôt"),
    (r"\bd'accuse de\b", "d'accusé de"),
    (r"\bAccuser reception\b", "Accuser réception"),
    (r"\bAccuse reception\b", "Accuse réception"),
    (r"\baccuse reception\b", "accuse réception"),
    (r"\bmontant propose\b", "montant proposé"),
    (r"\bmontant approuve\b", "montant approuvé"),
    (r"\bdossier valide\b", "dossier validé"),
    (r"\brapport valide\b", "rapport validé"),
    (r"\badvisory redige\b", "advisory rédigé"),
    (r"\bdelai consomme\b", "délai consommé"),
    (r"\bcompte cree\b", "compte créé"),
    (r"\bcomptes crees\b", "comptes créés"),
    (r"\bpassages listes\b", "passages listés"),
    (r"\bl'analyste designe devient\b", "l'analyste désigné devient"),
    (r"\bmessage argumente\b", "message argumenté"),
    (r"\breserve a un\b", "réservé à un"),
    (r"\bplafonne a\b", "plafonné à"),
    (r"\bdossier eleve\b", "dossier élevé"),
    (r"\bchiffre PGP\b", "chiffré PGP"),
    (r"\bPGP chiffre\b", "PGP chiffré"),
    (r"\bcomme chiffre\b", "comme chiffré"),
    (r"\brapport chiffre\b", "rapport chiffré"),
    (r"\bRapport chiffre\b", "Rapport chiffré"),
    (r"\bstocke en clair\b", "stocké en clair"),
    (r"\bmentionne comme anonyme\b", "mentionné comme anonyme"),
    (r"\bfinira rejete\b", "finira rejeté"),
    (r"\bexecutable deguise\b", "exécutable déguisé"),
    (r"\bexecutable renomme\b", "exécutable renommé"),
    (r"\bversement effectue\b", "versement effectué"),
    (r"\bpaiement effectue\b", "paiement effectué"),
    (r"\bformat normalise\b", "format normalisé"),
    (r"\bn'est jamais invente\b", "n'est jamais inventé"),
    (r"\brien n'est fige\b", "rien n'est figé"),
    (r"\bqui different\b", "qui diffèrent"),
    (r"\bhors plateforme par\b", "hors plateforme par"),
    (r"\bcredit public mentionne\b", "crédit public mentionné"),
    (r"\bactif retenu\b", "actif retenu"),
    (r"\bscore calcule\b", "score calculé"),
    (r"\best calcule\b", "est calculé"),
    (r"\bsont rattaches\b", "sont rattachés"),
    (r"\bpre-calculee\b", "pré-calculée"),
    (r"\bcontre-verification\b", "contre-vérification"),
    (r"\bsont notifies\b", "sont notifiés"),
    (r"\best notifie\b", "est notifié"),
    (r"\best informe\b", "est informé"),
    (r"\best journalise\b", "est journalisé"),
    (r"\best refuse\b", "est refusé"),
    (r"\bsont refuses\b", "sont refusés"),
    (r"\best realise\b", "est réalisé"),
    (r"\best redige\b", "est rédigé"),
    (r"\bredige pour l'occasion\b", "rédigé pour l'occasion"),
    (r"\best reserve\b", "est réservé"),
    (r"\best exige\b", "est exigé"),
    (r"\bne sera plus modifiee\b", "ne sera plus modifiée"),
    (r"\bjamais modifie\b", "jamais modifié"),
    (r"\bjamais modifiee\b", "jamais modifiée"),
    (r"\bdeja tranchee\b", "déjà tranchée"),
    (r"\ba J\\+", "à J+"),
    (r"\bcorrectif verifie\b", "correctif vérifié"),
    (r"\bCorrectif verifie\b", "Correctif vérifié"),
    (r"\badvisory publie\b", "advisory publié"),
    (r"\bAdvisory publie\b", "Advisory publié"),
    (r"\bchercheur identifie\b", "chercheur identifié"),
    (r"\bsaisi et justifie\b", "saisi et justifié"),
    (r"\bnon sollicite\b", "non sollicité"),
    (r"\breporte dans\b", "reporté dans"),
    (r"\brappele au depot\b", "rappelé au dépôt"),
    (r"\bEtre connecte\b", "Être connecté"),
    (r"\bcompte metier\b", "compte métier"),
    (r"\bsignalement anonyme\b", "signalement anonyme"),
    (r"\bcontenu assaini\b", "contenu assaini"),
    (r"\bbrouillon assaini\b", "brouillon assaini"),
    (r"\bdossier publie avec\b", "dossier publié avec"),
    (r"\bprogramme publie,", "programme publié,"),
    (r"\best traite selon\b", "est traité selon"),
    (r"\brelu, publie\b", "relu, publié"),
    (r"\betre publie\b", "être publié"),
    (r"\ben <b>Publie</b>", "en <b>Publié</b>"),
    (r"\bcompte verifie\b", "compte vérifié"),
    (r"\bdisponible ou verifie\b", "disponible ou vérifié"),
    (r"\bfourni et verifie\b", "fourni et vérifié"),
    (r"\bdisponible et verifie\b", "disponible et vérifié"),
    (r"\bpuis Approuve\b", "puis Approuvé"),
    (r"proposé, approuve, verse", "proposé, approuvé, versé"),
    (r"\bAdvisory redige\b", "Advisory rédigé"),
    (r"\bNon exige\b", "Non exigé"),
    (r"\bAccepte par defaut\b", "Accepté par défaut"),
    (r"\best accepte\b", "est accepté"),
    (r"\bdelais annonces\b", "délais annoncés"),
    (r"\bDes la\b", "Dès la"),
    (r"\bDes le\b", "Dès le"),
    (r"\bmal forme\b", "mal formé"),
    (r"\best recalcule\b", "est recalculé"),
    (r"\bcorrection envisage\b", "correction envisagé"),
    (r"\bMontant suggere nul\b", "Montant suggéré nul"),
    (r"\bL'analyste designe devient\b", "L'analyste désigné devient"),
    (r"\best associe a\b", "est associé à"),
    (r"\bCree la recompense\b", "Crée la récompense"),
    (r"\bCree les comptes\b", "Crée les comptes"),
    (r"\bA l'envoi\b", "À l'envoi"),
    (r"\bA l'issue\b", "À l'issue"),
    (r"\bA la publication\b", "À la publication"),
    (r"\bA la validation\b", "À la validation"),
    (r"^L'analyste designe$", "L'analyste désigné"),
    (r"\bDeclarant notifie\b", "Déclarant notifié"),
    (r"\bn'execute\b", "n'exécute"),
    (r"\bil est rattache au\b", "il est rattaché au"),
    (r"\brattache au precedent\b", "rattaché au précédent"),
    (r"\betre retire\b", "être retiré"),
    (r"\bjalons marques\b", "jalons marqués"),
    (r"\bmessage chiffre\b", "message chiffré"),
    (r"\bfichier accepte\b", "fichier accepté"),
    (r"\bil est assume\b", "il est assumé"),
    (r"\bOu travailler\b", "Où travailler"),
    (r"\btout juste arrive\b", "tout juste arrivé"),
    (r"\bA la publication\b", "À la publication"),
    (r"\bA l'envoi\b", "À l'envoi"),
    (r"\bNon sollicite\b", "Non sollicité"),
    (r"\bSollicite par message\b", "Sollicité par message"),
    (r"\baura ete informe\b", "aura été informé"),
    (r"\bsont marques publics\b", "sont marqués publics"),
    (r"\best applique au\b", "est appliqué au"),
    (r"\bqu'acces refuse\b", "qu'accès refusé"),
    (r"\benvoye au declarant\b", "envoyé au déclarant"),
    (r"\bTexte affiche sur\b", "Texte affiché sur"),
    (r"<b>retire</b>", "<b>retiré</b>"),
    (r"\bcelui affiche a l'ecran\b", "celui affiché à l'écran"),
    (r"\ble declarant informe\b", "le déclarant informé"),
    (r"\bsafe harbor\b", "safe harbor"),
]

#: Participes passes : la forme nue se confond avec un present, on ne
#: l'accentue donc que dans les tournures ou elle est bien un participe.
_PARTICIPES = (
    "propose|approuve|publie|verifie|modifie|refuse|informe|journalise|valide|"
    "redige|chiffre|stocke|realise|rejete|calcule|demontre|invente|mentionne|"
    "fige|consomme|argumente|renomme|deguise|sollicite|reporte|effectue|"
    "normalise|identifie|justifie|rappele|envoye|connecte|attribue|enregistre|"
    "assigne|marque|pose|cree|designe|declare|note|verse|signale|corrige|"
    "conserve|livre|prononce"
)
_ACCENT_PARTICIPE = {
    "propose": "proposé",
    "approuve": "approuvé",
    "publie": "publié",
    "verifie": "vérifié",
    "modifie": "modifié",
    "refuse": "refusé",
    "informe": "informé",
    "journalise": "journalisé",
    "valide": "validé",
    "redige": "rédigé",
    "chiffre": "chiffré",
    "stocke": "stocké",
    "realise": "réalisé",
    "rejete": "rejeté",
    "calcule": "calculé",
    "demontre": "démontré",
    "invente": "inventé",
    "mentionne": "mentionné",
    "fige": "figé",
    "consomme": "consommé",
    "argumente": "argumenté",
    "renomme": "renommé",
    "deguise": "déguisé",
    "sollicite": "sollicité",
    "reporte": "reporté",
    "effectue": "effectué",
    "normalise": "normalisé",
    "identifie": "identifié",
    "justifie": "justifié",
    "rappele": "rappelé",
    "envoye": "envoyé",
    "connecte": "connecté",
    "attribue": "attribué",
    "enregistre": "enregistré",
    "assigne": "assigné",
    "marque": "marqué",
    "pose": "posé",
    "cree": "créé",
    "designe": "désigné",
    "declare": "déclaré",
    "note": "noté",
    "verse": "versé",
    "signale": "signalé",
    "corrige": "corrigé",
    "conserve": "conservé",
    "livre": "livré",
    "prononce": "prononcé",
}

#: Tournures ou le participe suit un auxiliaire ou un nom sans ambiguite.
_AVANT_PARTICIPE = [
    r"(?:est|sont|etait|etaient|soit|deja|jamais|bien|pas|toujours|"
    r"a ete|ont ete|a |l'a |qui l'a )",
]

#: Formes accentuees sans ambiguite. Cle en minuscules ; la majuscule
#: initiale du texte est reportee sur le remplacement.
_LEXIQUE = {
    "acceder": "accéder",
    "acceptee": "acceptée",
    "acces": "accès",
    "accordee": "accordée",
    "affectee": "affectée",
    "affichee": "affichée",
    "agregee": "agrégée",
    "ajoutes": "ajoutés",
    "alertes": "alertes",
    "anciennete": "ancienneté",
    "annoncee": "annoncée",
    "annulee": "annulée",
    "annulees": "annulées",
    "anterieure": "antérieure",
    "anterieurs": "antérieurs",
    "apparait": "apparaît",
    "appliquees": "appliquées",
    "approuvee": "approuvée",
    "apres": "après",
    "arbitres": "arbitres",
    "armee": "armée",
    "armees": "armées",
    "arrete": "arrête",
    "arriere": "arrière",
    "arrivee": "arrivée",
    "arrivees": "arrivées",
    "assignee": "assignée",
    "assignes": "assignés",
    "associee": "associée",
    "attribuee": "attribuée",
    "aussitot": "aussitôt",
    "authentifiee": "authentifiée",
    "autorisee": "autorisée",
    "autorisees": "autorisées",
    "autorises": "autorisés",
    "avertissement": "avertissement",
    "bareme": "barème",
    "beneficient": "bénéficient",
    "boite": "boîte",
    "calculee": "calculée",
    "capacite": "capacité",
    "capacites": "capacités",
    "caracteres": "caractères",
    "chaine": "chaîne",
    "chiffrees": "chiffrées",
    "citees": "citées",
    "cites": "cités",
    "cle": "clé",
    "clot": "clôt",
    "cloture": "clôture",
    "collegue": "collègue",
    "collegues": "collègues",
    "complementaires": "complémentaires",
    "complete": "complète",
    "completee": "complétée",
    "concernee": "concernée",
    "confidentialite": "confidentialité",
    "confirmee": "confirmée",
    "connait": "connaît",
    "connaitre": "connaître",
    "consequence": "conséquence",
    "consequences": "conséquences",
    "conservee": "conservée",
    "consultee": "consultée",
    "contactee": "contactée",
    "controle": "contrôle",
    "controlee": "contrôlée",
    "controlees": "contrôlées",
    "controles": "contrôles",
    "coordonnee": "coordonnée",
    "corrigee": "corrigée",
    "corrigees": "corrigées",
    "cote": "côté",
    "cout": "coût",
    "couteuse": "coûteuse",
    "credit": "crédit",
    "credite": "crédité",
    "creditee": "créditée",
    "cree": "crée",
    "creee": "créée",
    "creees": "créées",
    "creer": "créer",
    "crees": "créés",
    "critere": "critère",
    "datee": "datée",
    "debut": "début",
    "dechiffrement": "déchiffrement",
    "decide": "décide",
    "decisif": "décisif",
    "decision": "décision",
    "decisions": "décisions",
    "declarant": "déclarant",
    "declarants": "déclarants",
    "declaratif": "déclaratif",
    "declaration": "déclaration",
    "declare": "déclare",
    "declaree": "déclarée",
    "declarer": "déclarer",
    "declenche": "déclenche",
    "deconnexion": "déconnexion",
    "decouler": "découler",
    "decouragerait": "découragerait",
    "decouverte": "découverte",
    "decouvre": "découvre",
    "decrit": "décrit",
    "decrite": "décrite",
    "dedie": "dédié",
    "dediee": "dédiée",
    "deduit": "déduit",
    "defaut": "défaut",
    "defavorable": "défavorable",
    "defense": "défense",
    "defini": "défini",
    "definir": "définir",
    "definitif": "définitif",
    "definitifs": "définitifs",
    "definitive": "définitive",
    "deja": "déjà",
    "dela": "delà",
    "delai": "délai",
    "delais": "délais",
    "deleguee": "déléguée",
    "delimite": "délimité",
    "demandees": "demandées",
    "demonstration": "démonstration",
    "depart": "départ",
    "depassee": "dépassée",
    "depassement": "dépassement",
    "depassements": "dépassements",
    "depasser": "dépasser",
    "dependance": "dépendance",
    "deplacer": "déplacer",
    "deploie": "déploie",
    "deploiement": "déploiement",
    "depose": "dépose",
    "deposee": "déposée",
    "deposees": "déposées",
    "deposer": "déposer",
    "depot": "dépôt",
    "derive": "dérive",
    "derniere": "dernière",
    "deroulent": "déroulent",
    "desactivee": "désactivée",
    "designe": "désigne",
    "designee": "désignée",
    "designes": "désignés",
    "detail": "détail",
    "detaille": "détaille",
    "detaillee": "détaillée",
    "detenue": "détenue",
    "determine": "détermine",
    "detient": "détient",
    "developpement": "développement",
    "differe": "diffère",
    "different": "diffèrent",
    "disparait": "disparaît",
    "dispenses": "dispensés",
    "distincte": "distincte",
    "donnee": "donnée",
    "donnees": "données",
    "ecarter": "écarter",
    "echanger": "échanger",
    "echanges": "échanges",
    "echeance": "échéance",
    "echeances": "échéances",
    "echecs": "échecs",
    "echoue": "échoue",
    "ecoulee": "écoulée",
    "ecran": "écran",
    "ecrans": "écrans",
    "ecrire": "écrire",
    "ecrit": "écrit",
    "ecrites": "écrites",
    "ecriture": "écriture",
    "editeur": "éditeur",
    "element": "élément",
    "elementaire": "élémentaire",
    "elements": "éléments",
    "eleve": "élevé",
    "elevee": "élevée",
    "encadre": "encadré",
    "engagee": "engagée",
    "enregistree": "enregistrée",
    "enregistrees": "enregistrées",
    "enrolement": "enrôlement",
    "enroler": "enrôler",
    "enterine": "entérine",
    "entite": "entité",
    "entree": "entrée",
    "envisagee": "envisagée",
    "equipe": "équipe",
    "errone": "erroné",
    "espere": "espère",
    "etabli": "établi",
    "etablie": "établie",
    "etablissement": "établissement",
    "etablissements": "établissements",
    "etape": "étape",
    "etapes": "étapes",
    "etat": "état",
    "etats": "états",
    "ete": "été",
    "etiquettes": "étiquettes",
    "etranger": "étranger",
    "etre": "être",
    "evenement": "événement",
    "evenements": "événements",
    "eventuel": "éventuel",
    "eventuelle": "éventuelle",
    "evident": "évident",
    "evite": "évite",
    "evolution": "évolution",
    "exclusivement": "exclusivement",
    "executable": "exécutable",
    "exigee": "exigée",
    "exiges": "exigés",
    "facon": "façon",
    "facons": "façons",
    "fenetre": "fenêtre",
    "figee": "figée",
    "filtree": "filtrée",
    "financiere": "financière",
    "fixee": "fixée",
    "forgee": "forgée",
    "formee": "formée",
    "francais": "français",
    "frequence": "fréquence",
    "frontiere": "frontière",
    "generalement": "généralement",
    "genere": "généré",
    "generee": "générée",
    "gerer": "gérer",
    "gestion": "gestion",
    "hypotheses": "hypothèses",
    "identifiee": "identifiée",
    "identite": "identité",
    "immediatement": "immédiatement",
    "incoherence": "incohérence",
    "integration": "intégration",
    "integre": "intègre",
    "interet": "intérêt",
    "intitule": "intitulé",
    "jointes": "jointes",
    "journalisee": "journalisée",
    "journalises": "journalisés",
    "laissee": "laissée",
    "lateral": "latéral",
    "legitime": "légitime",
    "levee": "levée",
    "libelle": "libellé",
    "limitees": "limitées",
    "listee": "listée",
    "listes": "listés",
    "livrees": "livrées",
    "majores": "majorés",
    "matiere": "matière",
    "mefier": "méfier",
    "meme": "même",
    "memes": "mêmes",
    "menage": "ménage",
    "mene": "mène",
    "metier": "métier",
    "metiers": "métiers",
    "ministere": "ministère",
    "ministeriel": "ministériel",
    "modele": "modèle",
    "modifiables": "modifiables",
    "modifiee": "modifiée",
    "motivee": "motivée",
    "necessaire": "nécessaire",
    "negocie": "négocie",
    "notifiee": "notifiée",
    "notifies": "notifiés",
    "numerique": "numérique",
    "numero": "numéro",
    "numerote": "numéroté",
    "obeit": "obéit",
    "operation": "opération",
    "operationnel": "opérationnel",
    "operations": "opérations",
    "parametrage": "paramétrage",
    "parametre": "paramètre",
    "parametres": "paramètres",
    "particularite": "particularité",
    "payee": "payée",
    "penalite": "pénalité",
    "percu": "perçu",
    "percus": "perçus",
    "perimetre": "périmètre",
    "perimetres": "périmètres",
    "periode": "période",
    "piece": "pièce",
    "pieces": "pièces",
    "plafonnee": "plafonnée",
    "planifiee": "planifiée",
    "planifier": "planifier",
    "plutot": "plutôt",
    "portee": "portée",
    "posee": "posée",
    "possibilite": "possibilité",
    "postee": "postée",
    "prealable": "préalable",
    "precedent": "précédent",
    "precis": "précis",
    "precise": "précise",
    "precisement": "précisément",
    "preciser": "préciser",
    "precision": "précision",
    "prefere": "préfère",
    "premiere": "première",
    "premieres": "premières",
    "preparation": "préparation",
    "prepare": "prépare",
    "presentee": "présentée",
    "pret": "prêt",
    "prevenu": "prévenu",
    "prevenue": "prévenue",
    "prevenues": "prévenues",
    "previent": "prévient",
    "prevu": "prévu",
    "prevue": "prévue",
    "prevues": "prévues",
    "priorite": "priorité",
    "priorites": "priorités",
    "prive": "privé",
    "privee": "privée",
    "procedure": "procédure",
    "prononcee": "prononcée",
    "proposee": "proposée",
    "publication": "publication",
    "publiee": "publiée",
    "publiees": "publiées",
    "publies": "publiés",
    "publiquement": "publiquement",
    "qualifie": "qualifie",
    "qualifiee": "qualifiée",
    "realisee": "réalisée",
    "recalcule": "recalcule",
    "recalculee": "recalculée",
    "recapitulatif": "récapitulatif",
    "reception": "réception",
    "recherche": "recherche",
    "recoit": "reçoit",
    "recompense": "récompense",
    "recompenser": "récompenser",
    "recompenses": "récompenses",
    "reconnait": "reconnaît",
    "recu": "reçu",
    "recues": "reçues",
    "redaction": "rédaction",
    "redige": "rédige",
    "rediger": "rédiger",
    "reduire": "réduire",
    "reelle": "réelle",
    "reellement": "réellement",
    "reevalue": "réévalue",
    "reference": "référence",
    "referencee": "référencée",
    "references": "références",
    "referme": "referme",
    "reflexe": "réflexe",
    "refusee": "refusée",
    "refusees": "refusées",
    "refuses": "refusés",
    "reglage": "réglage",
    "reglages": "réglages",
    "regle": "règle",
    "regles": "règles",
    "regression": "régression",
    "reguliere": "régulière",
    "rejete": "rejeté",
    "rejetee": "rejetée",
    "relecteur": "relecteur",
    "remediation": "remédiation",
    "reparti": "réparti",
    "repartit": "répartit",
    "repartition": "répartition",
    "repere": "repère",
    "reperee": "repérée",
    "repond": "répond",
    "repondent": "répondent",
    "repondre": "répondre",
    "reponse": "réponse",
    "reprend": "reprend",
    "represente": "représente",
    "representer": "représenter",
    "reproposee": "reproposée",
    "reputation": "réputation",
    "requete": "requête",
    "reserve": "réserve",
    "reservee": "réservée",
    "reservees": "réservées",
    "reserves": "réserves",
    "resolu": "résolu",
    "respectee": "respectée",
    "responsabilite": "responsabilité",
    "reste": "reste",
    "resume": "résumé",
    "retrocession": "rétrocession",
    "reunion": "réunion",
    "revele": "révèle",
    "reveler": "révéler",
    "reveles": "révélés",
    "reverifiee": "revérifiée",
    "reverifier": "revérifier",
    "role": "rôle",
    "roles": "rôles",
    "sceptre": "sceptre",
    "securisee": "sécurisée",
    "securite": "sécurité",
    "selection": "sélection",
    "selectionne": "sélectionne",
    "selectionner": "sélectionner",
    "separation": "séparation",
    "separee": "séparée",
    "separement": "séparément",
    "separent": "séparent",
    "sequence": "séquence",
    "severite": "sévérité",
    "severites": "sévérités",
    "signalee": "signalée",
    "signales": "signalés",
    "soldee": "soldée",
    "sollicitee": "sollicitée",
    "suggere": "suggère",
    "superieur": "supérieur",
    "superieure": "supérieure",
    "supplementaire": "supplémentaire",
    "systeme": "système",
    "telechargees": "téléchargées",
    "telechargement": "téléchargement",
    "teleservice": "téléservice",
    "televersees": "téléversées",
    "tentee": "tentée",
    "tete": "tête",
    "tracabilite": "traçabilité",
    "tracee": "tracée",
    "traine": "traîne",
    "traitee": "traitée",
    "tranchee": "tranchée",
    "triee": "triée",
    "verifiable": "vérifiable",
    "verification": "vérification",
    "verifiee": "vérifiée",
    "verifiees": "vérifiées",
    "verifier": "vérifier",
    "verifies": "vérifiés",
    "visee": "visée",
    "visibilite": "visibilité",
    "vulnerabilite": "vulnérabilité",
    "vulnerabilites": "vulnérabilités",
}

_MOTIF_LEXIQUE = _re.compile(
    r"(?<![\wÀ-ſ])(" + "|".join(sorted(_LEXIQUE, key=len, reverse=True)) + r")(?![\wÀ-ſ])",
    _re.IGNORECASE,
)
_MOTIF_PARTICIPE = _re.compile(
    r"\b(est|sont|etait|etaient|soit|deja|jamais|bien|toujours|a ete|ont ete)"
    r"(\s+(?:pas\s+|jamais\s+|deja\s+|bien\s+)?)(" + _PARTICIPES + r")\b",
    _re.IGNORECASE,
)
_SENTINELLE = "{}"


def _report_casse(source, cible):
    """Reporte la majuscule initiale du mot d'origine sur le mot accentue."""
    if source[:1].isupper():
        return cible[:1].upper() + cible[1:]
    return cible


def acc(texte):
    """Repose les accents d'un fragment destine au lecteur."""
    if not texte or not isinstance(texte, str):
        return texte

    # 1. Les tournures ou "a" est le verbe avoir sont mises a l'abri.
    protege = {}
    for index, (brut, accentue) in enumerate(_VERBE_A):
        marque = _SENTINELLE.format(index)
        # Bornes de mot obligatoires : sans elles, "a pu" se reconnaissait
        # au milieu de "la publication", qui perdait son accent.
        motif = r"\b" + _re.escape(brut) + r"\b"
        if _re.search(motif, texte):
            texte = _re.sub(motif, marque, texte)
            protege[marque] = accentue

    # 2. Les tournures a sens variable, puis la preposition. Cet ordre
    #    compte : une regle qui parle de "a" doit voir le mot d'origine.
    for motif, remplacement in _TOURNURES:
        texte = _re.sub(motif, remplacement, texte)
    texte = _re.sub(
        r"(?<![\w'À-ſ])a(?![\w'À-ſ])(?!\s+\w*é(?:e|s|es)?\b)",
        "à",
        texte,
    )

    # 3. Les participes passes, puis le lexique.
    def _participe(m):
        return m.group(1) + m.group(2) + _ACCENT_PARTICIPE[m.group(3).lower()]

    texte = _MOTIF_PARTICIPE.sub(_participe, texte)

    def _mot(m):
        source = m.group(1)
        if source.isupper() and len(source) > 1:
            return source  # identifiant d'etat ou de capacite
        return _report_casse(source, _LEXIQUE[source.lower()])

    texte = _MOTIF_LEXIQUE.sub(_mot, texte)

    for marque, accentue in protege.items():
        texte = texte.replace(marque, accentue)
    return texte


if __name__ == "__main__":
    main()
