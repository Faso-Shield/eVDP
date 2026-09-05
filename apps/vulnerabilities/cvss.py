"""Calculateur CVSS v3.1 (score de base).

Implementation autonome de la specification FIRST CVSS v3.1, section 8.1.
Aucun appel reseau : le score reste calculable hors ligne, conformement a
l'exigence "ne pas dependre d'une API externe pour le fonctionnement de base".

TODO : ajouter CVSS v4.0 (le format de vecteur est deja detecte et rejete
proprement pour eviter un score errone).
"""

import math

PREFIX_31 = "CVSS:3.1"
PREFIX_30 = "CVSS:3.0"

METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

METRIC_LABELS = {
    "AV": (
        "Vecteur d'attaque",
        {"N": "Reseau", "A": "Adjacent", "L": "Local", "P": "Physique"},
    ),
    "AC": ("Complexite d'attaque", {"L": "Faible", "H": "Elevee"}),
    "PR": ("Privileges requis", {"N": "Aucun", "L": "Faibles", "H": "Eleves"}),
    "UI": ("Interaction utilisateur", {"N": "Aucune", "R": "Requise"}),
    "S": ("Portee", {"U": "Inchangee", "C": "Modifiee"}),
    "C": ("Confidentialite", {"H": "Elevee", "L": "Faible", "N": "Aucune"}),
    "I": ("Integrite", {"H": "Elevee", "L": "Faible", "N": "Aucune"}),
    "A": ("Disponibilite", {"H": "Elevee", "L": "Faible", "N": "Aucune"}),
}

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}

DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"


class CVSSError(ValueError):
    """Vecteur CVSS invalide."""


def parse_vector(vector):
    """Analyse un vecteur CVSS v3.x et retourne le dict des metriques de base."""
    if not vector:
        raise CVSSError("Vecteur CVSS vide.")
    raw = vector.strip().upper()
    if raw.startswith("CVSS:4"):
        raise CVSSError("CVSS v4.0 n'est pas encore pris en charge par le calculateur eVDP.")
    parts = raw.split("/")
    if not parts or parts[0] not in (PREFIX_31, PREFIX_30):
        raise CVSSError("Le vecteur doit commencer par CVSS:3.1/ ou CVSS:3.0/.")
    metrics = {}
    for chunk in parts[1:]:
        if ":" not in chunk:
            raise CVSSError(f"Metrique illisible: {chunk!r}")
        key, _, value = chunk.partition(":")
        metrics[key] = value
    missing = [m for m in METRIC_ORDER if m not in metrics]
    if missing:
        raise CVSSError("Metriques de base manquantes: " + ", ".join(missing))
    for key in METRIC_ORDER:
        allowed = METRIC_LABELS[key][1]
        if metrics[key] not in allowed:
            raise CVSSError(
                f"Valeur invalide pour {key}: {metrics[key]!r} "
                f"(attendu: {'/'.join(allowed)})"
            )
    return {key: metrics[key] for key in METRIC_ORDER}


def _round_up1(value):
    """Arrondi superieur au dixieme, conforme a la spec CVSS v3.1."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def base_score(vector):
    """Retourne le score de base CVSS v3.1 (0.0 - 10.0)."""
    metrics = parse_vector(vector)
    scope_changed = metrics["S"] == "C"

    iss = 1 - (
        (1 - WEIGHTS["C"][metrics["C"]])
        * (1 - WEIGHTS["I"][metrics["I"]])
        * (1 - WEIGHTS["A"][metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = (
        8.22
        * WEIGHTS["AV"][metrics["AV"]]
        * WEIGHTS["AC"][metrics["AC"]]
        * PR_WEIGHTS["C" if scope_changed else "U"][metrics["PR"]]
        * WEIGHTS["UI"][metrics["UI"]]
    )

    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10)
    else:
        score = min(impact + exploitability, 10)
    return _round_up1(score)


def severity_from_score(score):
    from .constants import Severity

    return Severity.from_score(score)


def describe(vector):
    """Decompose un vecteur en libelles lisibles pour l'interface."""
    metrics = parse_vector(vector)
    return [
        {
            "code": key,
            "label": METRIC_LABELS[key][0],
            "value": metrics[key],
            "value_label": METRIC_LABELS[key][1][metrics[key]],
        }
        for key in METRIC_ORDER
    ]


def build_vector(metrics):
    """Construit un vecteur normalise a partir d'un dict de metriques."""
    missing = [m for m in METRIC_ORDER if not metrics.get(m)]
    if missing:
        raise CVSSError("Metriques manquantes: " + ", ".join(missing))
    body = "/".join(f"{key}:{metrics[key].upper()}" for key in METRIC_ORDER)
    vector = f"{PREFIX_31}/{body}"
    base_score(vector)  # validation
    return vector


def evaluate(vector):
    """Retourne (score, severite) ou (None, None) si le vecteur est absent."""
    if not vector:
        return None, None
    score = base_score(vector)
    return score, severity_from_score(score)
