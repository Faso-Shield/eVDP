"""Tests de la cle PGP nationale (apps.core.pgp)."""

from apps.core.pgp import national_fingerprint, national_public_key


def test_national_public_key_unescapes_newlines(settings):
    """PGP_PUBLIC_KEY est stockee sur une seule ligne (\\n echappes) car
    docker-compose ne supporte pas les valeurs multi-lignes dans sa
    substitution ${VAR} : sans reconversion, le bloc telecharge n'est pas
    un fichier .asc valide pour un client GPG standard."""
    settings.EVDP = {
        **settings.EVDP,
        "PGP_PUBLIC_KEY": (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\\n\\nmQINBFO...\\n"
            "-----END PGP PUBLIC KEY BLOCK-----"
        ),
    }
    key = national_public_key()
    assert "\\n" not in key
    assert key.splitlines()[0] == "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    assert key.splitlines()[-1] == "-----END PGP PUBLIC KEY BLOCK-----"


def test_national_public_key_empty_by_default(settings):
    settings.EVDP = {**settings.EVDP, "PGP_PUBLIC_KEY": ""}
    assert national_public_key() == ""


def test_national_fingerprint_stripped(settings):
    settings.EVDP = {**settings.EVDP, "PGP_FINGERPRINT": "  ABCD 1234  "}
    assert national_fingerprint() == "ABCD 1234"
