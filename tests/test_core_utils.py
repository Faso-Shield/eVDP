"""Tests des utilitaires transverses (apps.core.utils)."""

import threading

import pytest

from apps.coordination.models import Case
from apps.core.utils import next_sequence

pytestmark = pytest.mark.django_db


def test_next_sequence_increments():
    first = next_sequence(Case, "case_id", "TESTSEQ", year=2099)
    second = next_sequence(Case, "case_id", "TESTSEQ", year=2099)
    third = next_sequence(Case, "case_id", "TESTSEQ", year=2099)
    assert first == "TESTSEQ-2099-000001"
    assert second == "TESTSEQ-2099-000002"
    assert third == "TESTSEQ-2099-000003"


def test_next_sequence_is_isolated_per_year_and_model():
    from apps.disclosures.models import Advisory

    case_value = next_sequence(Case, "case_id", "TESTSEQ", year=2099)
    advisory_value = next_sequence(Advisory, "advisory_id", "TESTSEQ", year=2099)
    other_year_value = next_sequence(Case, "case_id", "TESTSEQ", year=2100)
    assert case_value == "TESTSEQ-2099-000001"
    # Meme prefixe/annee, mais modele different : compteur independant.
    assert advisory_value == "TESTSEQ-2099-000001"
    # Meme prefixe/modele, annee differente : compteur independant.
    assert other_year_value == "TESTSEQ-2100-000001"


@pytest.mark.django_db(transaction=True)
def test_next_sequence_has_no_collision_under_concurrent_calls():
    """Regression : l'ancienne implementation derivait le prochain numero du
    "dernier" enregistrement existant sous select_for_update(), ce qui ne
    verrouillait qu'une ligne deja committee. Deux appels strictement
    simultanes pouvaient alors lire le meme "dernier" numero et renvoyer
    litteralement la meme valeur, provoquant un IntegrityError a la creation
    du second Case. Le compteur dedie doit garantir zero collision, meme
    sous acces concurrent reel (threads + connexions separees).

    SQLite ne verrouille pas au niveau ligne (un seul ecrivain a la fois pour
    toute la base) : ce test n'est donc significatif que sur PostgreSQL, la
    cible de production (voir README.md, section Tests). Sur SQLite il est
    ignore plutot que rendu flaky par les "database is locked" du moteur
    lui-meme, qui ne refletent pas le comportement du verrou de ligne teste.
    """
    from django.db import connection

    if connection.vendor != "postgresql":
        pytest.skip("Verrouillage ligne reel : significatif seulement sur PostgreSQL.")

    results = []
    errors = []
    start_barrier = threading.Barrier(8)

    def worker():
        try:
            start_barrier.wait(timeout=5)
            value = next_sequence(Case, "case_id", "RACESEQ", year=2098)
            results.append(value)
        except Exception as exc:  # pragma: no cover - failure path asserted below
            errors.append(exc)
        finally:
            connection.close()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors, f"Erreurs inattendues : {errors}"
    assert len(results) == 8
    assert len(set(results)) == 8, f"Collision detectee : {results}"
