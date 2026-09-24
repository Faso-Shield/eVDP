"""Referentiel geographique du Burkina Faso pour la cartographie.

Une organisation est placee sur la carte a partir de ses coordonnees
precises si elles sont renseignees, sinon au chef-lieu de sa region. Le
repli evite qu'une organisation disparaisse de la carte faute de
geolocalisation, sans inventer de precision : `precise` le dit au lecteur.

Les regions sont reconnues sous leur nom d'avant la reforme de 2025 (13
regions, celui des donnees deja saisies) comme sous leur nouveau nom (17
regions). Les deux designations d'une meme region pointent sur le meme
chef-lieu, pour qu'un changement de nom ne deplace rien sur la carte.
"""

import unicodedata

# Emprise du territoire, avec une marge : sert a valider une saisie et a
# borner la carte.
LAT_MIN, LAT_MAX = 9.3, 15.2
LON_MIN, LON_MAX = -5.6, 2.5

# Centre par defaut : Ouagadougou.
DEFAULT_CENTER = (12.3714, -1.5197)

# (nom affiche, chef-lieu, latitude, longitude, anciens noms reconnus)
REGIONS = [
    ("Kadiogo", "Ouagadougou", 12.3714, -1.5197, ["Centre"]),
    ("Guiriko", "Bobo-Dioulasso", 11.1771, -4.2979, ["Hauts-Bassins"]),
    ("Bankui", "Dédougou", 12.4634, -3.4608, ["Boucle du Mouhoun"]),
    ("Tannounyan", "Banfora", 10.6333, -4.7667, ["Cascades"]),
    ("Kuilsé", "Kaya", 13.0917, -1.0844, ["Centre-Nord"]),
    ("Nakambé", "Tenkodogo", 11.7800, -0.3697, ["Centre-Est"]),
    ("Nando", "Koudougou", 12.2526, -2.3627, ["Centre-Ouest"]),
    ("Nazinon", "Manga", 11.6636, -1.0731, ["Centre-Sud"]),
    ("Goulmou", "Fada N'Gourma", 12.0616, 0.3584, ["Est"]),
    ("Yaadga", "Ouahigouya", 13.5828, -2.4216, ["Nord"]),
    ("Oubri", "Ziniaré", 12.5822, -1.2983, ["Plateau-Central", "Plateau Central"]),
    ("Liptako", "Dori", 14.0354, -0.0345, ["Sahel"]),
    ("Djôrô", "Gaoua", 10.3250, -3.1750, ["Sud-Ouest"]),
    ("Sirba", "Bogandé", 12.9714, -0.1436, []),
    ("Soum", "Djibo", 14.1022, -1.6306, []),
    ("Sourou", "Tougan", 13.0686, -3.0703, []),
    ("Tapoa", "Diapaga", 12.0708, 1.7889, []),
]


def _normalize(name):
    """Cle de comparaison : sans accents, casse ni separateurs."""
    decomposed = unicodedata.normalize("NFKD", name or "")
    ascii_only = "".join(c for c in decomposed if not unicodedata.combining(c))
    return "".join(c for c in ascii_only.lower() if c.isalnum())


_INDEX = {}
for _name, _capital, _lat, _lon, _aliases in REGIONS:
    _entry = {"name": _name, "capital": _capital, "lat": _lat, "lon": _lon}
    for _key in [_name, _capital, *_aliases]:
        _INDEX[_normalize(_key)] = _entry


def find_region(name):
    """Region correspondant a `name` (nom actuel, ancien nom ou chef-lieu)."""
    return _INDEX.get(_normalize(name)) if name else None


def region_label(name):
    """Nom actuel de la region, ou la saisie telle quelle si inconnue."""
    region = find_region(name)
    return region["name"] if region else (name or "").strip()


def in_burkina(lat, lon):
    return LAT_MIN <= float(lat) <= LAT_MAX and LON_MIN <= float(lon) <= LON_MAX


def locate(organization):
    """Position cartographique d'une organisation, ou None.

    Rend `(lat, lon, precise)` ; `precise` vaut False quand la position est
    celle du chef-lieu de region.
    """
    if organization.latitude is not None and organization.longitude is not None:
        return float(organization.latitude), float(organization.longitude), True
    region = find_region(organization.region)
    if region:
        return region["lat"], region["lon"], False
    return None
