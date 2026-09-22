"""Amorce la plateforme avec des donnees reelles (pas de demonstration).

A la difference de `seed_demo`, cette commande ne cree ni compte, ni
signalement, ni programme fictif : uniquement les donnees de reference et
les organisations reelles necessaires pour commencer a utiliser la
plateforme en conditions reelles.

Usage :
    python manage.py seed_reference

Idempotente : peut etre relancee sans dupliquer (utilise get_or_create).

Note sur les organisations : les champs de contact (email officiel,
responsable DSI, responsable d'organisation) sont volontairement laisses
vides. Ils sont a completer depuis l'interface (fiche de l'organisation)
avec les vraies coordonnees, ou via l'invitation d'un membre reel.
"""

from decimal import Decimal

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import User
from apps.coordination.models import SLAPolicy
from apps.core.models import SiteSetting
from apps.core.views import DEFAULT_DISCLOSURE_POLICY
from apps.organizations.models import Organization, OrganizationType, Sector
from apps.programs.models import (
    ConfidentialityLevel,
    Program,
    ProgramRule,
    ProgramScope,
    ProgramStatus,
    ProgramType,
    RewardPolicy,
    RewardTier,
    RuleKind,
    ScopePriority,
    ScopeTargetType,
)
from apps.vulnerabilities.constants import Severity
from apps.vulnerabilities.models import CWE

REWARD_MATRIX = [
    (Severity.CRITICAL, 750000, 2000000, "Impact national, compromission majeure"),
    (Severity.HIGH, 300000, 750000, "Compromission de donnees ou de comptes"),
    (Severity.MEDIUM, 100000, 300000, "Impact limite ou exploitation conditionnee"),
    (Severity.LOW, 0, 100000, "Impact faible, defense en profondeur"),
]

CWE_SEED = [
    ("CWE-79", "Improper Neutralization of Input During Web Page Generation (XSS)"),
    ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command"),
    ("CWE-287", "Improper Authentication"),
    ("CWE-285", "Improper Authorization"),
    ("CWE-639", "Authorization Bypass Through User-Controlled Key (IDOR)"),
    ("CWE-918", "Server-Side Request Forgery (SSRF)"),
    ("CWE-352", "Cross-Site Request Forgery (CSRF)"),
    ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
    ("CWE-94", "Improper Control of Generation of Code (Code Injection)"),
    ("CWE-16", "Configuration"),
    ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    ("CWE-98", "Improper Control of Filename for Include/Require Statement"),
    ("CWE-840", "Business Logic Errors"),
]

# Autorite nationale de cybersecurite et CSIRT national : ce sont les
# vraies entites qui pilotent eVDP, pas des donnees de demonstration.
NATIONAL_ENTITIES = [
    {
        "name": "Agence Nationale de Securite des Systemes d'Information",
        "acronym": "ANSSI-BF",
        "organization_type": OrganizationType.PUBLIC_INSTITUTION,
        "sector": Sector.GOVERNMENT,
        "domain": "anssi.bf",
        "region": "Centre",
        "description": "Autorite nationale de cybersecurite du Burkina Faso.",
    },
    {
        "name": "CSIRT National",
        "acronym": "CSIRT-BF",
        "organization_type": OrganizationType.PUBLIC_INSTITUTION,
        "sector": Sector.DEFENSE,
        "domain": "csirt.bf",
        "region": "Centre",
        "description": "Equipe nationale de reponse aux incidents de securite.",
    },
]

# Liste standard des principaux ministeres sectoriels du Burkina Faso.
# Les intitules exacts de portefeuille evoluent au gre des remaniements :
# a verifier/ajuster si besoin depuis l'interface (fiche de l'organisation).
# Domaines au format .gov.bf indicatif, a confirmer aupres de chaque DSI.
MINISTRIES = [
    ("Ministere de la Sante et de l'Hygiene Publique", "MS", Sector.HEALTH, "sante.gov.bf"),
    (
        "Ministere de l'Education Nationale, de l'Alphabetisation "
        "et de la Promotion des Langues Nationales",
        "MENAPLN",
        Sector.EDUCATION,
        "education.gov.bf",
    ),
    (
        "Ministere de l'Economie, des Finances et de la Prospective",
        "MEFP",
        Sector.FINANCE,
        "finances.gov.bf",
    ),
    (
        "Ministere de la Defense et des Anciens Combattants",
        "MDAC",
        Sector.DEFENSE,
        "defense.gov.bf",
    ),
    ("Ministere de la Securite", "MS-SECU", Sector.DEFENSE, "securite.gov.bf"),
    (
        "Ministere de l'Administration Territoriale, de la Decentralisation "
        "et de la Mobilite",
        "MATDM",
        Sector.GOVERNMENT,
        "administration-territoriale.gov.bf",
    ),
    (
        "Ministere des Affaires Etrangeres et de la Cooperation Regionale",
        "MAECR",
        Sector.GOVERNMENT,
        "affaires-etrangeres.gov.bf",
    ),
    (
        "Ministere de la Justice et des Droits Humains",
        "MJDH",
        Sector.JUSTICE,
        "justice.gov.bf",
    ),
    (
        "Ministere de l'Agriculture, des Ressources Animales et Halieutiques",
        "MARAH",
        Sector.AGRICULTURE,
        "agriculture.gov.bf",
    ),
    ("Ministere de l'Eau et de l'Assainissement", "MEA", Sector.WATER, "eau.gov.bf"),
    (
        "Ministere de l'Energie, des Mines et des Carrieres",
        "MEMC",
        Sector.ENERGY,
        "energie.gov.bf",
    ),
    (
        "Ministere des Infrastructures et du Desenclavement",
        "MID",
        Sector.TRANSPORT,
        "infrastructures.gov.bf",
    ),
    (
        "Ministere du Commerce, de l'Industrie et de l'Artisanat",
        "MCIA",
        Sector.INDUSTRY,
        "commerce.gov.bf",
    ),
    (
        "Ministere de la Communication, de la Culture, des Arts et du Tourisme",
        "MCCAT",
        Sector.OTHER,
        "communication.gov.bf",
    ),
    (
        "Ministere de la Fonction Publique, du Travail et de la Protection Sociale",
        "MFPTPS",
        Sector.GOVERNMENT,
        "fonction-publique.gov.bf",
    ),
]


class Command(BaseCommand):
    help = "Amorce eVDP avec des donnees reelles : referentiel CWE, SLA, ministeres."

    def add_arguments(self, parser):
        parser.add_argument(
            "--with-programs",
            action="store_true",
            help=(
                "Cree aussi un programme VDP national et deux programmes Bug Bounty "
                "realistes, rattaches aux vraies organisations (pas de faux comptes "
                "ni de faux dossiers crees)."
            ),
        )

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write("Chargement du referentiel CWE…")
        for code, name in CWE_SEED:
            CWE.objects.get_or_create(code=code, defaults={"name": name})

        self.stdout.write("Politique SLA nationale par defaut…")
        sla, _ = SLAPolicy.objects.get_or_create(
            name="SLA national par defaut",
            defaults={
                "is_default": True,
                "acknowledgement_hours": 72,
                "triage_days": 5,
                "vendor_response_days": 7,
                "remediation_days_critical": 30,
                "remediation_days_high": 30,
                "remediation_days_medium": 60,
                "remediation_days_low": 90,
                "disclosure_delay_days": 90,
            },
        )

        self.stdout.write("Textes de la plateforme (politique de divulgation, a propos)…")
        SiteSetting.objects.get_or_create(
            key="disclosure_policy",
            defaults={
                "label": "Politique nationale de divulgation",
                "value": DEFAULT_DISCLOSURE_POLICY,
            },
        )
        SiteSetting.objects.get_or_create(
            key="about",
            defaults={
                "label": "A propos de eVDP",
                "value": (
                    "## eVDP\n\n"
                    "eVDP est la plateforme nationale de divulgation coordonnee de "
                    "vulnerabilites et de gestion des programmes Bug Bounty du "
                    "Burkina Faso (projet CYBER-DEF 2).\n\n"
                    "Elle offre aux chercheurs, aux citoyens et aux professionnels "
                    "un canal officiel, securise et juridiquement encadre pour "
                    "signaler une vulnerabilite affectant un service public ou une "
                    "infrastructure numerique nationale.\n\n"
                    "### Missions\n\n"
                    "- Recevoir et qualifier les signalements de vulnerabilites.\n"
                    "- Coordonner la remediation avec les organisations affectees.\n"
                    "- Piloter des programmes VDP et Bug Bounty nationaux.\n"
                    "- Publier des advisories assainis apres coordination.\n"
                    "- Produire la posture nationale de vulnerabilites.\n"
                ),
            },
        )

        self.stdout.write("Entites nationales (ANSSI-BF, CSIRT National)…")
        entities = {}
        for spec in NATIONAL_ENTITIES:
            org, _ = Organization.objects.get_or_create(name=spec["name"], defaults=spec)
            entities[spec["acronym"]] = org

        self.stdout.write(f"Ministeres ({len(MINISTRIES)})…")
        ministries = {}
        for name, acronym, sector, domain in MINISTRIES:
            org, _ = Organization.objects.get_or_create(
                name=name,
                defaults={
                    "acronym": acronym,
                    "organization_type": OrganizationType.MINISTRY,
                    "sector": sector,
                    "domain": domain,
                    "region": "Centre",
                    "accepts_vdp": True,
                },
            )
            ministries[acronym] = org

        if options["with_programs"]:
            self.stdout.write("Programmes (1 VDP national + 2 Bug Bounty)…")
            self._programs(entities, ministries, sla)

        self.stdout.write(self.style.SUCCESS("\nDonnees de reference chargees."))
        self.stdout.write(
            self.style.WARNING(
                "\nÀ completer depuis l'interface pour chaque organisation : email "
                "officiel, responsable DSI, responsable d'organisation — via "
                "'Ajouter un membre' sur la fiche de l'organisation, ou en modifiant "
                "directement ses coordonnees."
            )
        )

    # -------------------------------------------------------------- programmes
    def _programs(self, entities, ministries, sla):
        """Un programme VDP national et deux Bug Bounty realistes.

        Rattaches aux vraies organisations (ANSSI-BF, CSIRT National, un
        ministere) : aucun faux compte, aucun faux dossier n'est cree ici.
        """
        creator = User.objects.filter(is_superuser=True).order_by("created_at").first()

        vdp, created = Program.objects.get_or_create(
            name="Programme National VDP",
            defaults={
                "program_type": ProgramType.VDP,
                "organization": entities["ANSSI-BF"],
                "status": ProgramStatus.ACTIVE,
                "confidentiality": ConfidentialityLevel.PUBLIC,
                "summary": "Canal officiel de signalement des vulnerabilites des services publics.",
                "description": (
                    "Le Programme National VDP permet a toute personne de signaler "
                    "une vulnerabilite affectant un service numerique de "
                    "l'administration burkinabe.\n\n"
                    "Aucune recompense financiere n'est associee a ce programme : "
                    "son objectif est de faciliter la divulgation responsable et de "
                    "proteger les usagers des services publics."
                ),
                "rules": (
                    "- Limitez vos tests au strict necessaire pour demontrer la faille.\n"
                    "- N'alterez, ne supprimez et n'exfiltrez aucune donnee.\n"
                    "- N'utilisez jamais d'outil de test de charge ou de deni de service.\n"
                    "- Signalez sans delai et conservez la confidentialite."
                ),
                "out_of_scope_notes": (
                    "Sont exclus : l'ingenierie sociale, le hameconnage, le deni de "
                    "service, les attaques physiques, le spam, ainsi que toute donnee "
                    "personnelle obtenue illegalement."
                ),
                "safe_harbor": (
                    "Toute recherche conduite de bonne foi et conforme a la presente "
                    "politique est consideree comme autorisee. Aucune poursuite ne "
                    "sera engagee a l'encontre d'un chercheur respectant ces regles."
                ),
                "disclosure_policy": (
                    "La divulgation coordonnee intervient au plus tard 90 jours apres "
                    "la validation du signalement, sauf accord contraire."
                ),
                "sla_policy": sla,
                "disclosure_delay_days": 90,
                "allows_anonymous_reports": True,
                "starts_on": timezone.localdate(),
                "created_by": creator,
            },
        )
        if created:
            for identifier, description in [
                ("*.gov.bf", "Ensemble des domaines gouvernementaux."),
                ("Applications gouvernementales", "Applications metiers de l'administration."),
                ("APIs publiques", "Interfaces exposees par les administrations."),
            ]:
                ProgramScope.objects.create(
                    program=vdp,
                    in_scope=True,
                    target_type=ScopeTargetType.DOMAIN,
                    identifier=identifier,
                    description=description,
                    priority=ScopePriority.P2,
                    environment="Production",
                )
            ProgramScope.objects.create(
                program=vdp,
                in_scope=False,
                target_type=ScopeTargetType.OTHER,
                identifier="Ingenierie sociale",
                description="Toute manipulation d'agents publics.",
            )
            ProgramRule.objects.create(
                program=vdp,
                kind=RuleKind.PROHIBITED,
                title="Aucune exfiltration de donnees",
                body="La demonstration doit s'arreter des que la faille est prouvee.",
            )

        bounty_national, created = Program.objects.get_or_create(
            name="Bug Bounty National - Services Publics",
            defaults={
                "program_type": ProgramType.BUG_BOUNTY,
                "organization": entities["CSIRT-BF"],
                "status": ProgramStatus.ACTIVE,
                "confidentiality": ConfidentialityLevel.PUBLIC,
                "summary": "Programme remunere sur les services publics critiques.",
                "description": (
                    "Ce programme recompense la decouverte de vulnerabilites sur un "
                    "perimetre restreint de services publics critiques.\n\n"
                    "Les montants sont fixes par la matrice de recompenses ci-contre "
                    "et arretes apres validation technique."
                ),
                "rules": (
                    "- Un seul rapport par vulnerabilite.\n"
                    "- Les doublons ne donnent pas lieu a recompense.\n"
                    "- Les rapports automatises sans impact demontre sont ecartes."
                ),
                "eligibility": (
                    "- Etre inscrit sur eVDP avec une adresse email verifiee.\n"
                    "- Ne pas etre agent de l'organisation concernee.\n"
                    "- Respecter integralement les regles de test."
                ),
                "safe_harbor": (
                    "Le Safe Harbor du Programme National VDP s'applique integralement "
                    "a ce programme."
                ),
                "sla_policy": sla,
                "disclosure_delay_days": 60,
                "allows_anonymous_reports": False,
                "requires_verified_email": True,
                "starts_on": timezone.localdate(),
                "created_by": creator,
            },
        )
        if created:
            for identifier, target_type, priority in [
                ("api.services.gov.bf", ScopeTargetType.API, ScopePriority.P1),
                ("portail.services.gov.bf", ScopeTargetType.DOMAIN, ScopePriority.P1),
                ("Application mobile eServices", ScopeTargetType.MOBILE_APP, ScopePriority.P2),
            ]:
                ProgramScope.objects.create(
                    program=bounty_national,
                    in_scope=True,
                    target_type=target_type,
                    identifier=identifier,
                    priority=priority,
                    environment="Production",
                )
            policy = RewardPolicy.objects.create(
                program=bounty_national, currency="XOF", total_budget=Decimal("25000000")
            )
            for severity, minimum, maximum, description in REWARD_MATRIX:
                RewardTier.objects.create(
                    policy=policy,
                    severity=severity,
                    min_amount=Decimal(minimum),
                    max_amount=Decimal(maximum),
                    description=description,
                )

        bounty_sante, created = Program.objects.get_or_create(
            name="Bug Bounty - Plateforme e-Sante",
            defaults={
                "program_type": ProgramType.BUG_BOUNTY,
                "organization": ministries["MS"],
                "status": ProgramStatus.ACTIVE,
                "confidentiality": ConfidentialityLevel.PUBLIC,
                "summary": "Programme remunere sur les plateformes numeriques de sante.",
                "description": (
                    "Ce programme recompense la decouverte de vulnerabilites sur le "
                    "portail e-sante et les services numeriques associes du "
                    "Ministere de la Sante et de l'Hygiene Publique.\n\n"
                    "Une attention particuliere est portee a la protection des "
                    "donnees de sante des usagers."
                ),
                "rules": (
                    "- Ne jamais consulter, modifier ou exfiltrer un dossier patient reel.\n"
                    "- Utiliser exclusivement les comptes de test fournis, le cas echeant.\n"
                    "- Signaler immediatement tout acces accidentel a une donnee reelle."
                ),
                "eligibility": (
                    "- Etre inscrit sur eVDP avec une adresse email verifiee.\n"
                    "- Respecter integralement les regles de test, renforcees pour "
                    "les donnees de sante."
                ),
                "safe_harbor": (
                    "Le Safe Harbor du Programme National VDP s'applique integralement "
                    "a ce programme."
                ),
                "sla_policy": sla,
                "disclosure_delay_days": 60,
                "allows_anonymous_reports": False,
                "requires_verified_email": True,
                "starts_on": timezone.localdate(),
                "created_by": creator,
            },
        )
        if created:
            for identifier, target_type, priority, description in [
                (
                    "portail.sante.gov.bf",
                    ScopeTargetType.DOMAIN,
                    ScopePriority.P1,
                    "Portail public e-sante.",
                ),
                (
                    "api.sante.gov.bf",
                    ScopeTargetType.API,
                    ScopePriority.P1,
                    "API dossier patient et rendez-vous.",
                ),
            ]:
                ProgramScope.objects.create(
                    program=bounty_sante,
                    in_scope=True,
                    target_type=target_type,
                    identifier=identifier,
                    priority=priority,
                    description=description,
                    environment="Production",
                )
            ProgramScope.objects.create(
                program=bounty_sante,
                in_scope=False,
                target_type=ScopeTargetType.OTHER,
                identifier="Donnees de sante reelles",
                description="Toute donnee patient reelle est strictement hors perimetre de test.",
            )
            policy = RewardPolicy.objects.create(
                program=bounty_sante, currency="XOF", total_budget=Decimal("15000000")
            )
            for severity, minimum, maximum, description in REWARD_MATRIX:
                RewardTier.objects.create(
                    policy=policy,
                    severity=severity,
                    min_amount=Decimal(minimum),
                    max_amount=Decimal(maximum),
                    description=description,
                )
