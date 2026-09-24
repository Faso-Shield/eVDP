"""Formulaires de traitement des cases."""

from django import forms
from django.core.exceptions import ValidationError

from apps.accounts.models import User
from apps.organizations.models import Organization, OrganizationStatus
from apps.programs.models import ProgramScope
from apps.vulnerabilities.constants import Severity
from apps.vulnerabilities.cvss import CVSSError, base_score
from apps.vulnerabilities.models import CVE, CWE

from .constants import Confidentiality
from .models import Case
from .workflow import CaseStatus


class CaseMessageForm(forms.Form):
    body = forms.CharField(
        label="Message",
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "Markdown autorisé…"}),
        max_length=20000,
    )
    confidentiality = forms.ChoiceField(label="Canal", choices=Confidentiality.choices)

    def __init__(self, *args, user=None, case=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Seuls les canaux ouverts en ecriture a cet utilisateur sont proposes
        # (matrice de visibilite) ; le service refait le controle.
        from .visibility import writable_channels

        allowed = writable_channels(case, user) if case is not None and user else []
        labels = dict(Confidentiality.choices)
        self.fields["confidentiality"].choices = [(c, labels[c]) for c in allowed]
        if allowed:
            self.fields["confidentiality"].initial = allowed[0]

    def clean_body(self):
        body = (self.cleaned_data.get("body") or "").strip()
        if not body:
            raise ValidationError("Le message ne peut pas être vide.")
        return body


class WorkflowActionForm(forms.Form):
    """Formulaire de confirmation d'une action de workflow.

    Les champs exiges par l'etape sont tous facultatifs ici : c'est le
    moteur (`workflow.check_transition`) qui dresse la liste de ce qui
    manque, afin que l'interface et l'API renvoient le meme message.
    """

    comment = forms.CharField(
        label="Commentaire", required=False, widget=forms.Textarea(attrs={"rows": 3})
    )
    # Etape 2 : checklist de recevabilite.
    in_scope = forms.BooleanField(label="Le signalement relève du périmètre", required=False)
    organization_identified = forms.BooleanField(
        label="L'organisation affectée est identifiée", required=False
    )
    attachment_readable = forms.BooleanField(
        label="La pièce jointe est lisible", required=False
    )
    # Etape 6 : plan de remediation.
    remediation_plan = forms.CharField(
        label="Plan de remédiation", required=False, widget=forms.Textarea(attrs={"rows": 4})
    )
    remediation_target_date = forms.DateField(
        label="Date cible", required=False, widget=forms.DateInput(attrs={"type": "date"})
    )
    # Etape 7 : correctif.
    fix_description = forms.CharField(
        label="Description du correctif",
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    fix_version = forms.CharField(label="Version corrigée", required=False, max_length=120)
    fix_deployed_on = forms.DateField(
        label="Date de déploiement",
        required=False,
        widget=forms.DateInput(attrs={"type": "date"}),
    )
    # Etape 8 : contre-verification.
    verification_report = forms.CharField(
        label="Compte rendu de contre-vérification",
        required=False,
        widget=forms.Textarea(attrs={"rows": 4}),
    )
    # Etape 10 : relecture.
    review_done = forms.BooleanField(label="Relecture de l'advisory effectuée", required=False)
    # Branche prime.
    amount = forms.DecimalField(
        label="Montant", required=False, max_digits=12, decimal_places=2, min_value=0
    )
    justification = forms.CharField(
        label="Justification (obligatoire hors palier)",
        required=False,
        widget=forms.Textarea(attrs={"rows": 2}),
    )
    # Doublon.
    original_case_id = forms.CharField(
        label="Dossier original (EVDP-…)", required=False, max_length=32
    )

    def __init__(self, *args, action=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.action = action
        if action is not None:
            # Sans action (API de compatibilite), tous les champs restent
            # acceptes ; le moteur ne lit que ceux de l'action resolue.
            keep = {"comment", *action.fields}
            for name in list(self.fields):
                if name not in keep:
                    del self.fields[name]
        if action is not None and action.comment_required:
            self.fields["comment"].label = "Commentaire (obligatoire)"

    def clean_original_case_id(self):
        case_id = (self.cleaned_data.get("original_case_id") or "").strip().upper()
        if not case_id:
            return None
        original = Case.objects.filter(case_id=case_id).first()
        if original is None:
            raise ValidationError("Aucun dossier ne correspond à cette référence.")
        return original

    def workflow_data(self):
        data = dict(self.cleaned_data)
        if "original_case_id" in data:
            data["original"] = data.pop("original_case_id")
        return data


class TriageForm(forms.Form):
    """Rattachement du dossier (agent de triage et analyste).

    Le champ `scope` n'existe que pour un case rattache a un programme : il
    designe l'actif du perimetre concerne, dont depend la grille de
    recompense quand celle-ci varie par actif. Le CVSS n'y figure pas : seul
    l'analyste le saisit (voir QualificationForm).
    """

    scope = forms.ModelChoiceField(
        label="Actif du périmètre",
        queryset=ProgramScope.objects.none(),
        required=False,
        help_text="Détermine la grille de récompense lorsqu'elle varie par actif.",
    )
    organization = forms.ModelChoiceField(
        label="Organisation affectée",
        queryset=Organization.objects.filter(status=OrganizationStatus.ACTIVE),
        required=False,
    )
    tags = forms.CharField(
        label="Étiquettes", required=False, help_text="Séparées par des virgules."
    )

    def __init__(self, *args, case=None, **kwargs):
        super().__init__(*args, **kwargs)
        program = getattr(case, "program", None)
        if program is None:
            # Un case hors programme n'a pas de perimetre : le champ
            # n'aurait aucun choix a proposer.
            del self.fields["scope"]
        else:
            self.fields["scope"].queryset = program.in_scope_targets()

    def clean_tags(self):
        raw = self.cleaned_data.get("tags") or ""
        return [tag.strip()[:40] for tag in raw.split(",") if tag.strip()][:12]


class QualificationForm(TriageForm):
    """Qualification technique de l'analyste CSIRT (etape 3)."""

    severity = forms.ChoiceField(label="Sévérité retenue", choices=Severity.choices)
    cvss_vector = forms.CharField(
        label="Vecteur CVSS v3.1 ou v4.0",
        required=False,
        max_length=255,
        help_text="CVSS:3.1/AV:N/… ou CVSS:4.0/AV:N/AC:L/AT:N/…",
    )
    cwe = forms.ModelChoiceField(label="CWE", queryset=CWE.objects.all(), required=False)

    field_order = ["severity", "cvss_vector", "cwe", "organization", "scope", "tags"]

    def clean_cvss_vector(self):
        vector = (self.cleaned_data.get("cvss_vector") or "").strip()
        if not vector:
            return ""
        try:
            base_score(vector)
        except CVSSError as exc:
            raise ValidationError(str(exc)) from exc
        return vector


class TransferForm(forms.Form):
    """Transfert d'un dossier pris en charge a un collegue du meme role."""

    target = forms.ModelChoiceField(label="Collègue", queryset=User.objects.none())
    note = forms.CharField(label="Note", required=False, max_length=255)

    def __init__(self, *args, candidates=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["target"].queryset = User.objects.filter(
            pk__in=[user.pk for user in candidates]
        ).order_by("full_name", "email")


class DuplicateForm(forms.Form):
    original_case_id = forms.CharField(label="Case original (EVDP-…)", max_length=32)
    comment = forms.CharField(
        label="Commentaire interne", required=False, widget=forms.Textarea(attrs={"rows": 2})
    )

    def clean_original_case_id(self):
        case_id = (self.cleaned_data.get("original_case_id") or "").strip().upper()
        original = Case.objects.filter(case_id=case_id).first()
        if original is None:
            raise ValidationError("Aucun case ne correspond à cette référence.")
        return original


class DisclosureScheduleForm(forms.Form):
    disclosure_date = forms.DateField(
        label="Date de divulgation", widget=forms.DateInput(attrs={"type": "date"})
    )


class CveLinkForm(forms.Form):
    cve_id = forms.CharField(label="Identifiant CVE", max_length=24)

    def clean_cve_id(self):
        value = (self.cleaned_data.get("cve_id") or "").strip().upper()
        cve, _ = CVE.objects.get_or_create(cve_id=value)
        return cve


class CaseFilterForm(forms.Form):
    """Filtres de la liste des cases (recherche globale incluse)."""

    q = forms.CharField(label="Recherche", required=False)
    status = forms.ChoiceField(
        label="Statut",
        required=False,
        choices=[("", "Tous les statuts")] + list(CaseStatus.choices),
    )
    severity = forms.ChoiceField(
        label="Sévérité",
        required=False,
        choices=[("", "Toutes severites")] + list(Severity.choices),
    )
    organization = forms.ModelChoiceField(
        label="Organisation",
        required=False,
        queryset=Organization.objects.all(),
        empty_label="Toutes les organisations",
    )
