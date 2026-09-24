"""Calculateur CVSS v4.0 (score CVSS-B / BT / BE / BTE).

Implementation autonome de la specification FIRST CVSS v4.0, section 8.2
(methode des macro-vecteurs et interpolation par distance de severite),
alignee sur le calculateur de reference FIRST. Aucun appel reseau.

Les metriques supplementaires (S, AU, R, V, RE, U) sont acceptees mais
n'influencent pas le score, conformement a la specification.
"""

from decimal import ROUND_HALF_UP, Decimal

from .cvss4_lookup import LOOKUP

PREFIX_40 = "CVSS:4.0"

BASE_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

_IMPACT = {"H": "Élevé", "L": "Faible", "N": "Aucun"}

METRIC_LABELS = {
    "AV": (
        "Vecteur d'attaque",
        {"N": "Réseau", "A": "Adjacent", "L": "Local", "P": "Physique"},
    ),
    "AC": ("Complexité d'attaque", {"L": "Faible", "H": "Élevée"}),
    "AT": ("Prérequis d'attaque", {"N": "Aucun", "P": "Présents"}),
    "PR": ("Privilèges requis", {"N": "Aucun", "L": "Faibles", "H": "Élevés"}),
    "UI": ("Interaction utilisateur", {"N": "Aucune", "P": "Passive", "A": "Active"}),
    "VC": ("Confidentialité (système vulnérable)", _IMPACT),
    "VI": ("Intégrité (système vulnérable)", _IMPACT),
    "VA": ("Disponibilité (système vulnérable)", _IMPACT),
    "SC": ("Confidentialité (systèmes aval)", _IMPACT),
    "SI": ("Intégrité (systèmes aval)", _IMPACT),
    "SA": ("Disponibilité (systèmes aval)", _IMPACT),
}

_X = {"X"}
_REQ = _X | {"H", "M", "L"}
#: Valeurs admises pour les metriques optionnelles (menace, environnement,
#: supplementaires). "X" = non defini.
OPTIONAL_VALUES = {
    "E": _X | {"A", "P", "U"},
    "CR": _REQ,
    "IR": _REQ,
    "AR": _REQ,
    "MAV": _X | {"N", "A", "L", "P"},
    "MAC": _X | {"L", "H"},
    "MAT": _X | {"N", "P"},
    "MPR": _X | {"N", "L", "H"},
    "MUI": _X | {"N", "P", "A"},
    "MVC": _X | {"H", "L", "N"},
    "MVI": _X | {"H", "L", "N"},
    "MVA": _X | {"H", "L", "N"},
    "MSC": _X | {"H", "L", "N"},
    "MSI": _X | {"S", "H", "L", "N"},
    "MSA": _X | {"S", "H", "L", "N"},
    "S": _X | {"N", "P"},
    "AU": _X | {"N", "Y"},
    "R": _X | {"A", "U", "I"},
    "V": _X | {"D", "C"},
    "RE": _X | {"L", "M", "H"},
    "U": _X | {"CLEAR", "GREEN", "AMBER", "RED"},
}

# Vecteurs "maximaux" de chaque classe d'equivalence (spec, tableau 24-29).
_MAX_COMPOSED = {
    1: {
        0: ["AV:N/PR:N/UI:N"],
        1: ["AV:A/PR:N/UI:N", "AV:N/PR:L/UI:N", "AV:N/PR:N/UI:P"],
        2: ["AV:P/PR:N/UI:N", "AV:A/PR:L/UI:P"],
    },
    2: {0: ["AC:L/AT:N"], 1: ["AC:H/AT:N", "AC:L/AT:P"]},
    # EQ3 et EQ6 sont indissociables : cle (eq3, eq6).
    36: {
        (0, 0): ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H"],
        (0, 1): ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M"],
        (1, 0): ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H"],
        (1, 1): [
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M",
        ],
        (2, 1): ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H"],
    },
    4: {0: ["SC:H/SI:S/SA:S"], 1: ["SC:H/SI:H/SA:H"], 2: ["SC:L/SI:L/SA:L"]},
}

# Profondeur maximale (en pas de 0,1) de chaque classe d'equivalence.
_MAX_SEVERITY = {
    1: {0: 1, 1: 4, 2: 5},
    2: {0: 1, 1: 2},
    36: {(0, 0): 7, (0, 1): 6, (1, 0): 8, (1, 1): 8, (2, 1): 10},
    4: {0: 6, 1: 5, 2: 4},
}

# Niveaux de severite par metrique (0 = le plus severe).
_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

_EQ_METRICS = {
    1: ("AV", "PR", "UI"),
    2: ("AC", "AT"),
    36: ("VC", "VI", "VA", "CR", "IR", "AR"),
    4: ("SC", "SI", "SA"),
}


def parse_vector(vector, error_cls=ValueError):
    """Analyse un vecteur CVSS:4.0 et retourne le dict de ses metriques."""
    raw = (vector or "").strip()
    parts = raw.split("/")
    if not parts or parts[0].upper() != PREFIX_40:
        raise error_cls("Le vecteur doit commencer par CVSS:4.0/.")
    metrics = {}
    for chunk in parts[1:]:
        key, sep, value = chunk.partition(":")
        key, value = key.upper(), value.upper()
        if not sep or not key or not value:
            raise error_cls(f"Metrique illisible: {chunk!r}")
        if key in metrics:
            raise error_cls(f"Metrique en double: {key}")
        if key in METRIC_LABELS:
            allowed = METRIC_LABELS[key][1]
        elif key in OPTIONAL_VALUES:
            allowed = OPTIONAL_VALUES[key]
        else:
            raise error_cls(f"Metrique inconnue: {key}")
        if value not in allowed:
            raise error_cls(
                f"Valeur invalide pour {key}: {value!r} (attendu: {'/'.join(sorted(allowed))})"
            )
        metrics[key] = value
    missing = [m for m in BASE_METRICS if m not in metrics]
    if missing:
        raise error_cls("Metriques de base manquantes: " + ", ".join(missing))
    return metrics


def _effective(metrics):
    """Valeurs effectives : metrique modifiee si definie, sinon valeur de base."""

    def m(key):
        selected = metrics.get(key, "X")
        if key == "E" and selected == "X":
            return "A"
        if key in ("CR", "IR", "AR") and selected == "X":
            return "H"
        modified = metrics.get("M" + key, "X")
        if modified != "X":
            return modified
        return selected

    keys = list(_LEVELS) + ["E"]
    values = {key: m(key) for key in keys}
    # MSI / MSA "S" (Safety) n'existe qu'en environnemental.
    values["MSI"] = metrics.get("MSI", "X")
    values["MSA"] = metrics.get("MSA", "X")
    return values


def _macro_vector(v):
    if v["AV"] == "N" and v["PR"] == "N" and v["UI"] == "N":
        eq1 = 0
    elif (v["AV"] == "N" or v["PR"] == "N" or v["UI"] == "N") and v["AV"] != "P":
        eq1 = 1
    else:
        eq1 = 2

    eq2 = 0 if (v["AC"] == "L" and v["AT"] == "N") else 1

    if v["VC"] == "H" and v["VI"] == "H":
        eq3 = 0
    elif "H" in (v["VC"], v["VI"], v["VA"]):
        eq3 = 1
    else:
        eq3 = 2

    if v["MSI"] == "S" or v["MSA"] == "S":
        eq4 = 0
    elif "H" in (v["SC"], v["SI"], v["SA"]):
        eq4 = 1
    else:
        eq4 = 2

    eq5 = {"A": 0, "P": 1, "U": 2}[v["E"]]

    eq6 = (
        0
        if (
            (v["CR"] == "H" and v["VC"] == "H")
            or (v["IR"] == "H" and v["VI"] == "H")
            or (v["AR"] == "H" and v["VA"] == "H")
        )
        else 1
    )
    return eq1, eq2, eq3, eq4, eq5, eq6


def _key(eqs):
    return "".join(str(e) for e in eqs)


def _lookup(eqs):
    return LOOKUP.get(_key(eqs))


def _round1(value):
    """Arrondi au dixieme, demi vers le haut (tolerance flottante incluse)."""
    return float(Decimal(value + 1e-6).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def base_score(vector, error_cls=ValueError):
    """Score CVSS v4.0 (0.0 - 10.0) selon les metriques presentes."""
    v = _effective(parse_vector(vector, error_cls))
    if all(v[k] == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    eqs = _macro_vector(v)
    eq1, eq2, eq3, eq4, eq5, eq6 = eqs
    value = _lookup(eqs)

    # Macro-vecteurs immediatement inferieurs, par classe d'equivalence.
    lower_eq1 = _lookup((eq1 + 1, eq2, eq3, eq4, eq5, eq6))
    lower_eq2 = _lookup((eq1, eq2 + 1, eq3, eq4, eq5, eq6))
    if eq3 == 0 and eq6 == 0:
        candidates = [
            _lookup((eq1, eq2, eq3, eq4, eq5, eq6 + 1)),
            _lookup((eq1, eq2, eq3 + 1, eq4, eq5, eq6)),
        ]
        candidates = [c for c in candidates if c is not None]
        lower_eq36 = max(candidates) if candidates else None
    elif eq3 == 1 and eq6 == 0:
        lower_eq36 = _lookup((eq1, eq2, eq3, eq4, eq5, eq6 + 1))
    elif eq6 == 1 and eq3 in (0, 1):
        lower_eq36 = _lookup((eq1, eq2, eq3 + 1, eq4, eq5, eq6))
    else:
        lower_eq36 = _lookup((eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1))
    lower_eq4 = _lookup((eq1, eq2, eq3, eq4 + 1, eq5, eq6))
    lower_eq5 = _lookup((eq1, eq2, eq3, eq4, eq5 + 1, eq6))

    # Premier vecteur maximal de la classe qui domine le vecteur evalue.
    distances = None
    for a in _MAX_COMPOSED[1][eq1]:
        for b in _MAX_COMPOSED[2][eq2]:
            for c in _MAX_COMPOSED[36][(eq3, eq6)]:
                for d in _MAX_COMPOSED[4][eq4]:
                    max_metrics = dict(
                        pair.split(":") for pair in "/".join((a, b, c, d)).split("/")
                    )
                    candidate = {
                        key: _LEVELS[key][v[key]] - _LEVELS[key][max_metrics[key]]
                        for key in _LEVELS
                    }
                    if all(dist >= 0 for dist in candidate.values()):
                        distances = candidate
                        break
                if distances:
                    break
            if distances:
                break
        if distances:
            break
    if distances is None:  # pragma: no cover - impossible avec la table FIRST
        distances = candidate

    step = 0.1
    parts = []
    for eq, lower, depth in (
        (1, lower_eq1, _MAX_SEVERITY[1][eq1]),
        (2, lower_eq2, _MAX_SEVERITY[2][eq2]),
        (36, lower_eq36, _MAX_SEVERITY[36][(eq3, eq6)]),
        (4, lower_eq4, _MAX_SEVERITY[4][eq4]),
    ):
        if lower is None or value - lower < 0:
            continue
        current = sum(distances[key] for key in _EQ_METRICS[eq])
        parts.append((value - lower) * current / (depth * step))
    if lower_eq5 is not None and value - lower_eq5 >= 0:
        # EQ5 (maturite de l'exploit) n'a pas de distance interne.
        parts.append(0.0)

    if parts:
        value -= sum(parts) / len(parts)
    return _round1(min(10.0, max(0.0, value)))


def describe(vector, error_cls=ValueError):
    metrics = parse_vector(vector, error_cls)
    return [
        {
            "code": key,
            "label": METRIC_LABELS[key][0],
            "value": metrics[key],
            "value_label": METRIC_LABELS[key][1][metrics[key]],
        }
        for key in BASE_METRICS
    ]
