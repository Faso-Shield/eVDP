"""Champs de date : la valeur existante doit s'afficher a l'edition.

<input type="date"> n'accepte que AAAA-MM-JJ (et datetime-local
AAAA-MM-JJTHH:MM). En fr-fr, Django rendait "30/09/2026" : le navigateur
affichait un champ vide et l'enregistrement effacait la date.
"""

import datetime

import pytest
from django import forms

from apps.coordination.forms import DisclosureScheduleForm, WorkflowActionForm
from apps.disclosures.forms import AdvisoryForm, AdvisoryTimelineFormSet
from apps.programs.forms import ProgramForm

DAY = datetime.date(2026, 9, 30)
MOMENT = datetime.datetime(2026, 9, 30, 14, 5)


@pytest.mark.parametrize(
    ("form_class", "field"),
    [
        (WorkflowActionForm, "remediation_target_date"),
        (WorkflowActionForm, "fix_deployed_on"),
        (DisclosureScheduleForm, "disclosure_date"),
        (ProgramForm, "starts_on"),
        (ProgramForm, "ends_on"),
        (AdvisoryTimelineFormSet.form, "happened_on"),
    ],
)
def test_date_widget_renders_iso(form_class, field):
    widget = form_class.base_fields[field].widget
    assert isinstance(widget, forms.DateInput)
    assert 'value="2026-09-30"' in widget.render(field, DAY)


def test_datetime_widget_renders_iso():
    widget = AdvisoryForm.base_fields["scheduled_for"].widget
    assert 'value="2026-09-30T14:05"' in widget.render("scheduled_for", MOMENT)


def test_iso_value_is_parsed_back():
    field = ProgramForm.base_fields["starts_on"]
    assert field.clean("2026-09-30") == DAY
