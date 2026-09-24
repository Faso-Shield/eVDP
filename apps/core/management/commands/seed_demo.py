"""Jeu de donnees de demonstration eVDP.

Usage :
    python manage.py seed_demo
    python manage.py seed_demo --reset   (supprime les donnees de demo)

Cette commande est idempotente : elle peut etre relancee sans dupliquer.
Les mots de passe de demonstration sont volontairement explicites et ne
doivent JAMAIS etre utilises en production (voir docs/installation.md).
"""

from datetime import timedelta
from decimal import Decimal

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import User
from apps.accounts.roles import Role
from apps.bounty.services import approve_bounty, propose_bounty
from apps.coordination.models import SLAPolicy
from apps.coordination.scenarios import Team, advance_case
from apps.coordination.services import transition_case
from apps.coordination.workflow import CaseBountyStatus, CaseStatus
from apps.core.models import SiteSetting
from apps.core.views import DEFAULT_DISCLOSURE_POLICY
from apps.disclosures.services import create_advisory_from_case
from apps.organizations.models import (
    MembershipRole,
    Organization,
    OrganizationMember,
    OrganizationType,
    Sector,
    SecurityContact,
)
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
from apps.reports.models import VulnerabilityReport
from apps.reports.services import submit_report
from apps.researchers.models import IdentityMode
from apps.researchers.services import get_or_create_profile
from apps.vulnerabilities.constants import Severity, VulnerabilityType
from apps.vulnerabilities.models import CWE

DEMO_PASSWORD = "EvdpDemo2026!"

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

REWARD_MATRIX = [
    (Severity.CRITICAL, 750000, 2000000, "Impact national, compromission majeure"),
    (Severity.HIGH, 300000, 750000, "Compromission de données ou de comptes"),
    (Severity.MEDIUM, 100000, 300000, "Impact limite ou exploitation conditionnee"),
    (Severity.LOW, 0, 100000, "Impact faible, defense en profondeur"),
]


class Command(BaseCommand):
    help = "Charge un jeu de données de démonstration eVDP."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Supprime les données de démonstration avant rechargement.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        if options["reset"]:
            self._reset()

        self.stdout.write("Chargement du referentiel CWE…")
        for code, name in CWE_SEED:
            CWE.objects.get_or_create(code=code, defaults={"name": name})

        self._site_settings()
        sla = self._sla_policy()
        organizations = self._organizations()
        users = self._users(organizations)
        programs = self._programs(organizations, sla, users)
        cases = self._cases(organizations, programs, users)
        self._workflow(cases, users)
        self._bounty(cases, users)
        self._advisory(cases, users)

        self.stdout.write(self.style.SUCCESS("\nJeu de démonstration chargé."))
        self.stdout.write("\nComptes de démonstration (mot de passe commun) :")
        self.stdout.write(f"  mot de passe : {DEMO_PASSWORD}")
        for label, email in [
            ("Administrateur", "admin@evdp.bf"),
            ("Coordinateur national", "coordinateur@anssi.bf"),
            ("Analyste CSIRT", "analyste@csirt.bf"),
            ("DSI ministere", "dsi@sante.gov.bf"),
            ("Chercheur", "researcher@demo.bf"),
            ("Chercheur Bug Bounty", "bugbounty@demo.bf"),
            ("Auditeur", "auditeur@evdp.bf"),
        ]:
            self.stdout.write(f"  {label:24s} {email}")
        self.stdout.write(
            self.style.WARNING(
                "\nCes identifiants sont destinés à la démonstration uniquement."
            )
        )

    # ------------------------------------------------------------------ reset
    def _reset(self):
        from django.db.models import QuerySet

        from apps.bounty.models import WalletEntry
        from apps.coordination.models import Case
        from apps.disclosures.models import Advisory

        self.stdout.write(self.style.WARNING("Suppression des données de démo…"))
        # Le grand livre refuse toute suppression (append-only) : la remise a
        # zero d'une base de DEMONSTRATION est la seule exception, explicite.
        QuerySet.delete(WalletEntry.objects.all())
        Advisory.objects.all().delete()
        Case.objects.all().delete()
        VulnerabilityReport.objects.all().delete()
        Program.objects.all().delete()
        Organization.objects.all().delete()
        User.objects.exclude(is_superuser=True).delete()

    # -------------------------------------------------------------- settings
    def _site_settings(self):
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
                    "eVDP est la plateforme nationale de divulgation coordonnée de "
                    "vulnérabilités et de gestion des programmes Bug Bounty du "
                    "Burkina Faso (projet CYBER-DEF 2).\n\n"
                    "Elle offre aux chercheurs, aux citoyens et aux professionnels "
                    "un canal officiel, securise et juridiquement encadré pour "
                    "signaler une vulnérabilité affectant un service public ou une "
                    "infrastructure numérique nationale.\n\n"
                    "### Missions\n\n"
                    "- Recevoir et qualifier les signalements de vulnérabilités.\n"
                    "- Coordonner la remédiation avec les organisations affectees.\n"
                    "- Piloter des programmes VDP et Bug Bounty nationaux.\n"
                    "- Publier des advisories assainis après coordination.\n"
                    "- Produire la posture nationale de vulnérabilités.\n"
                ),
            },
        )

    def _sla_policy(self):
        policy, _ = SLAPolicy.objects.get_or_create(
            name="SLA national par défaut",
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
        return policy

    # ---------------------------------------------------------- organisations
    def _organizations(self):
        specs = [
            {
                "name": "Agence Nationale de Sécurité des Systèmes d'Information",
                "acronym": "ANSSI-BF",
                "organization_type": OrganizationType.PUBLIC_INSTITUTION,
                "sector": Sector.GOVERNMENT,
                "domain": "anssi.bf",
                "official_email": "contact@anssi.bf",
                "region": "Centre",
                "description": "Autorite nationale de cybersecurite du Burkina Faso.",
            },
            {
                "name": "CSIRT National",
                "acronym": "CSIRT-BF",
                "organization_type": OrganizationType.PUBLIC_INSTITUTION,
                "sector": Sector.DEFENSE,
                "domain": "csirt.bf",
                "official_email": "cert@csirt.bf",
                "region": "Centre",
                "description": "Équipe nationale de réponse aux incidents de sécurité.",
            },
            {
                "name": "Ministère de démonstration",
                "acronym": "MINDEMO",
                "organization_type": OrganizationType.MINISTRY,
                "sector": Sector.HEALTH,
                "domain": "sante.gov.bf",
                "official_email": "dsi@sante.gov.bf",
                "region": "Centre",
                "description": "Ministère fictif utilise pour la démonstration.",
            },
            {
                "name": "Administration de démonstration",
                "acronym": "ADMDEMO",
                "organization_type": OrganizationType.PUBLIC_ADMIN,
                "sector": Sector.EDUCATION,
                "domain": "education.gov.bf",
                "official_email": "contact@education.gov.bf",
                "region": "Hauts-Bassins",
                "description": "Administration fictive utilisée pour la démonstration.",
            },
        ]
        organizations = {}
        for spec in specs:
            organization, _ = Organization.objects.get_or_create(
                name=spec["name"], defaults=spec
            )
            organizations[spec["acronym"]] = organization

        SecurityContact.objects.get_or_create(
            organization=organizations["MINDEMO"],
            email="securite@sante.gov.bf",
            defaults={
                "name": "Cellule sécurité MINDEMO",
                "role": "Contact securite",
                "is_primary": True,
            },
        )
        return organizations

    # ------------------------------------------------------------ utilisateurs
    def _users(self, organizations):
        specs = [
            ("admin@evdp.bf", "Administrateur eVDP", Role.SUPER_ADMIN, True, None),
            (
                "coordinateur@anssi.bf",
                "Coordinateur national",
                Role.NATIONAL_COORDINATOR,
                False,
                "ANSSI-BF",
            ),
            ("analyste@csirt.bf", "Analyste CSIRT", Role.CSIRT_ANALYST, False, "CSIRT-BF"),
            ("triage@csirt.bf", "Agent de triage", Role.TRIAGER, False, "CSIRT-BF"),
            ("dsi@sante.gov.bf", "DSI Ministere demo", Role.DSI_ADMIN, False, "MINDEMO"),
            (
                "responsable@education.gov.bf",
                "Responsable ADMDEMO",
                Role.ORGANIZATION_MANAGER,
                False,
                "ADMDEMO",
            ),
            ("researcher@demo.bf", "Researcher Demo", Role.SECURITY_RESEARCHER, False, None),
            (
                "bugbounty@demo.bf",
                "Security Researcher BF",
                Role.BUG_BOUNTY_RESEARCHER,
                False,
                None,
            ),
            ("auditeur@evdp.bf", "Auditeur national", Role.AUDITOR, False, "ANSSI-BF"),
        ]
        users = {}
        for email, name, role, is_admin, org_key in specs:
            user = User.objects.filter(email=email).first()
            if user is None:
                if is_admin:
                    user = User.objects.create_superuser(
                        email=email, password=DEMO_PASSWORD, full_name=name
                    )
                else:
                    user = User.objects.create_user(
                        email=email, password=DEMO_PASSWORD, full_name=name, role=role
                    )
                user.email_verified = True
                user.save(update_fields=["email_verified", "updated_at"])
            users[email] = user

            if org_key:
                membership_role = {
                    Role.DSI_ADMIN: MembershipRole.DSI,
                    Role.ORGANIZATION_MANAGER: MembershipRole.MANAGER,
                }.get(role, MembershipRole.ANALYST)
                OrganizationMember.objects.get_or_create(
                    organization=organizations[org_key],
                    user=user,
                    defaults={"membership_role": membership_role, "is_primary": True},
                )

        get_or_create_profile(
            users["researcher@demo.bf"],
            pseudonym="r3s34rch3r",
            identity_mode=IdentityMode.PSEUDONYM,
            is_public_profile=True,
            country="Burkina Faso",
            biography="Chercheur independant specialise en securite applicative web.",
        )
        get_or_create_profile(
            users["bugbounty@demo.bf"],
            pseudonym="bb-hunter-bf",
            identity_mode=IdentityMode.PUBLIC,
            is_public_profile=True,
            country="Burkina Faso",
            affiliation="Universite Joseph Ki-Zerbo",
            biography="Chasseur de bugs, spécialisé API et cloud.",
        )
        return users

    # --------------------------------------------------------------- programmes
    def _programs(self, organizations, sla, users):
        vdp, created = Program.objects.get_or_create(
            name="Programme National VDP",
            defaults={
                "program_type": ProgramType.VDP,
                "organization": organizations["ANSSI-BF"],
                "status": ProgramStatus.ACTIVE,
                "confidentiality": ConfidentialityLevel.PUBLIC,
                "summary": "Canal officiel de signalement des vulnérabilités des services publics.",
                "description": (
                    "Le Programme National VDP permet à toute personne de signaler "
                    "une vulnérabilité affectant un service numérique de "
                    "l'administration burkinabe.\n\n"
                    "Aucune récompense financière n'est associée à ce programme : "
                    "son objectif est de faciliter la divulgation responsable et de "
                    "proteger les usagers des services publics."
                ),
                "rules": (
                    "- Limitez vos tests au strict nécessaire pour démontrer la faille.\n"
                    "- N'altérez, ne supprimez et n'exfiltrez aucune donnée.\n"
                    "- N'utilisez jamais d'outil de test de charge ou de déni de service.\n"
                    "- Signalez sans délai et conservez la confidentialité."
                ),
                "out_of_scope_notes": (
                    "Sont exclus : l'ingénierie sociale, le hameçonnage, le déni de "
                    "service, les attaques physiques, le spam, ainsi que toute donnée "
                    "personnelle obtenue illegalement."
                ),
                "safe_harbor": (
                    "Toute recherche conduite de bonne foi et conforme à la présente "
                    "politique est consideree comme autorisée. Aucune poursuite ne "
                    "sera engagée à l'encontre d'un chercheur respectant ces règles."
                ),
                "disclosure_policy": (
                    "La divulgation coordonnée intervient au plus tard 90 jours après "
                    "la validation du signalement, sauf accord contraire."
                ),
                "contact_email": "vdp@anssi.bf",
                "sla_policy": sla,
                "disclosure_delay_days": 90,
                "allows_anonymous_reports": True,
                "starts_on": timezone.localdate() - timedelta(days=180),
                "created_by": users["coordinateur@anssi.bf"],
            },
        )
        if created:
            for identifier, description in [
                ("*.gov.bf", "Ensemble des domaines gouvernementaux."),
                ("*.gouv.bf", "Domaines gouvernementaux alternatifs."),
                ("Applications gouvernementales", "Applications métiers de l'administration."),
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
            for identifier, description in [
                ("Ingenierie sociale", "Toute manipulation d'agents publics."),
                ("Déni de service (DDoS)", "Tests de charge et saturation interdits."),
                ("Infrastructures tierces", "Prestataires non couverts par le programme."),
            ]:
                ProgramScope.objects.create(
                    program=vdp,
                    in_scope=False,
                    target_type=ScopeTargetType.OTHER,
                    identifier=identifier,
                    description=description,
                )
            ProgramRule.objects.create(
                program=vdp,
                kind=RuleKind.PROHIBITED,
                title="Aucune exfiltration de données",
                body="La démonstration doit s'arrêter des que la faille est prouvée.",
            )

        bounty, created = Program.objects.get_or_create(
            name="Bug Bounty National - Services Publics",
            defaults={
                "program_type": ProgramType.BUG_BOUNTY,
                "organization": organizations["CSIRT-BF"],
                "status": ProgramStatus.ACTIVE,
                "confidentiality": ConfidentialityLevel.PUBLIC,
                "summary": "Programme rémunéré sur les services publics critiques.",
                "description": (
                    "Ce programme récompense la découverte de vulnérabilités sur un "
                    "périmètre restreint de services publics critiques.\n\n"
                    "Les montants sont fixes par la matrice de récompenses ci-contre "
                    "et arretes après validation technique."
                ),
                "rules": (
                    "- Un seul rapport par vulnérabilité.\n"
                    "- Les doublons ne donnent pas lieu à récompense.\n"
                    "- Les rapports automatises sans impact demontre sont ecartes."
                ),
                "eligibility": (
                    "- Être inscrit sur eVDP avec une adresse email vérifiée.\n"
                    "- Ne pas être agent de l'organisation concernée.\n"
                    "- Respecter intégralement les règles de test."
                ),
                "safe_harbor": (
                    "Le Safe Harbor du Programme National VDP s'applique intégralement "
                    "à ce programme."
                ),
                "contact_email": "bugbounty@csirt.bf",
                "sla_policy": sla,
                "disclosure_delay_days": 60,
                "allows_anonymous_reports": False,
                "requires_verified_email": True,
                "starts_on": timezone.localdate() - timedelta(days=60),
                "created_by": users["coordinateur@anssi.bf"],
            },
        )
        if created:
            for identifier, target_type, priority in [
                ("api.services.gov.bf", ScopeTargetType.API, ScopePriority.P1),
                ("portail.services.gov.bf", ScopeTargetType.DOMAIN, ScopePriority.P1),
                ("Application mobile eServices", ScopeTargetType.MOBILE_APP, ScopePriority.P2),
            ]:
                ProgramScope.objects.create(
                    program=bounty,
                    in_scope=True,
                    target_type=target_type,
                    identifier=identifier,
                    priority=priority,
                    environment="Production",
                )
            ProgramScope.objects.create(
                program=bounty,
                in_scope=False,
                target_type=ScopeTargetType.DOMAIN,
                identifier="test.services.gov.bf",
                description="Environnement de test, hors périmètre.",
            )
            policy = RewardPolicy.objects.create(
                program=bounty, currency="XOF", total_budget=Decimal("25000000")
            )
            for severity, minimum, maximum, description in REWARD_MATRIX:
                RewardTier.objects.create(
                    policy=policy,
                    severity=severity,
                    min_amount=Decimal(minimum),
                    max_amount=Decimal(maximum),
                    description=description,
                )
            # Grille propre a un actif : l'API porte les donnees d'etat civil,
            # une faille critique y vaut trois fois le tarif general. Les
            # autres cibles restent sur la grille par defaut.
            api = bounty.scopes.filter(identifier="api.services.gov.bf").first()
            if api is not None:
                RewardTier.objects.create(
                    policy=policy,
                    scope=api,
                    severity=Severity.CRITICAL,
                    min_amount=Decimal("2500000"),
                    max_amount=Decimal("6000000"),
                    description="Actif de production critique.",
                )

        return {"vdp": vdp, "bounty": bounty}

    # -------------------------------------------------------------------- cases
    def _cases(self, organizations, programs, users):
        if VulnerabilityReport.objects.exists():
            from apps.coordination.models import Case

            return list(Case.objects.order_by("case_id")[:3])

        specs = [
            {
                "title": "Injection SQL sur le portail de demande d'acte de naissance",
                "product": "Portail e-Etat civil",
                "organization": organizations["MINDEMO"],
                "program": programs["vdp"],
                "reporter": users["researcher@demo.bf"],
                "vulnerability_type": VulnerabilityType.SQLI,
                "cwe": "CWE-89",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "target_url": "https://demo.sante.gov.bf/etat-civil/recherche",
                "description": (
                    "Le paramètre `numero` de la recherche d'acte de naissance n'est "
                    "pas filtre. Une injection SQL booleenne permet d'extraire le "
                    "contenu de la base applicative.\n\n"
                    "L'exploitation a été arretee dès la confirmation de la faille, "
                    "conformement à la politique de divulgation."
                ),
                "steps_to_reproduce": (
                    "1. Ouvrir la page de recherche d'acte de naissance.\n"
                    "2. Soumettre la valeur `1' AND 1=1--` dans le champ numéro.\n"
                    "3. Comparer avec `1' AND 1=2--` : la réponse diffère.\n"
                    "4. La difference confirme l'injection booleenne."
                ),
                "impact": (
                    "Un attaquant non authentifié peut extraire les données d'état "
                    "civil des usagers, incluant des données à caractère personnel."
                ),
                "recommendations": (
                    "Utiliser des requêtes paramétrées, appliquer une validation "
                    "stricte du paramètre et deployer un WAF en défense en profondeur."
                ),
                "requests_cve": True,
            },
            {
                "title": "IDOR permettant de consulter les dossiers d'autres usagers",
                "product": "Portail eServices",
                "organization": organizations["CSIRT-BF"],
                "program": programs["bounty"],
                "reporter": users["bugbounty@demo.bf"],
                "vulnerability_type": VulnerabilityType.IDOR,
                "cwe": "CWE-639",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "target_url": "https://api.services.gov.bf/v1/dossiers/{id}",
                "description": (
                    "L'endpoint de consultation d'un dossier ne vérifie pas que le "
                    "dossier appartient bien à l'utilisateur authentifié. En "
                    "incrementant l'identifiant, un usager accede aux dossiers "
                    "d'autres citoyens."
                ),
                "steps_to_reproduce": (
                    "1. S'authentifier avec un compte usager standard.\n"
                    "2. Appeler GET /v1/dossiers/1042 (dossier appartenant à un tiers).\n"
                    "3. Le contenu complet du dossier est retourne."
                ),
                "impact": (
                    "Accès non autorisé aux données administratives de l'ensemble "
                    "des usagers de la plateforme."
                ),
                "recommendations": (
                    "Vérifier la propriété de la ressource côté serveur et utiliser "
                    "des identifiants non enumerables (UUID)."
                ),
            },
            {
                "title": "En-têtes de sécurité absents sur le portail education",
                "product": "Portail education",
                "organization": organizations["ADMDEMO"],
                "program": programs["vdp"],
                "reporter": users["researcher@demo.bf"],
                "vulnerability_type": VulnerabilityType.MISCONFIGURATION,
                "cwe": "CWE-16",
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                "target_url": "https://demo.education.gov.bf/",
                "description": (
                    "Le portail ne renvoie ni Content-Security-Policy, ni HSTS, ni "
                    "X-Content-Type-Options. Cette absence facilite l'exploitation "
                    "d'autres vulnérabilités côté client."
                ),
                "impact": "Défense en profondeur affaiblie, risque accru de XSS exploitable.",
                "recommendations": (
                    "Deployer CSP, HSTS, X-Content-Type-Options, Referrer-Policy et "
                    "Permissions-Policy au niveau du reverse proxy."
                ),
            },
        ]

        cases = []
        for spec in specs:
            report = VulnerabilityReport(
                title=spec["title"],
                product=spec["product"],
                affected_organization=spec["organization"],
                program=spec["program"],
                target_url=spec["target_url"],
                vulnerability_type=spec["vulnerability_type"],
                cwe=CWE.objects.filter(code=spec["cwe"]).first(),
                cvss_vector=spec["cvss_vector"],
                description=spec["description"],
                steps_to_reproduce=spec.get("steps_to_reproduce", ""),
                impact=spec.get("impact", ""),
                recommendations=spec.get("recommendations", ""),
                requests_cve=spec.get("requests_cve", False),
                reporter=spec["reporter"],
                accepted_policy=True,
                wants_credit=True,
            )
            # Spec v2 : au moins une piece jointe par soumission.
            evidence = SimpleUploadedFile(
                "preuve.txt",
                f"Trace de reproduction - {spec['title']}".encode(),
                content_type="text/plain",
            )
            cases.append(
                submit_report(report, reporter=spec["reporter"], attachments=[evidence])
            )
        return cases

    # ----------------------------------------------------------------- workflow
    def _workflow(self, cases, users):
        analyst = users["analyste@csirt.bf"]
        coordinator = users["coordinateur@anssi.bf"]

        if not cases:
            return

        team = Team(
            triager=users["triage@csirt.bf"],
            analyst=analyst,
            validator=coordinator,
            vendor=users["dsi@sante.gov.bf"],
            publisher=coordinator,
        )

        # Case 1 : parcours CVD complet jusqu'a la verification du correctif
        # (etape 8), chaque etape jouee par son proprietaire.
        advance_case(cases[0], CaseStatus.FIX_VERIFIED, team)

        # Case 2 : parcours Bug Bounty jusqu'a la validation ; la branche
        # prime s'ouvre alors en parallele (voir _bounty).
        if len(cases) > 1:
            advance_case(cases[1], CaseStatus.VALIDATED, team)

        # Case 3 : en analyse, avec une demande de complements au declarant.
        # Rejouable : rien n'est redemande si le dossier a deja avance
        # (ou vient d'une base v1 migree, deja en NEEDS_INFORMATION).
        if len(cases) > 2:
            case = cases[2]
            advance_case(case, CaseStatus.IN_ANALYSIS, team)
            if case.status != CaseStatus.IN_ANALYSIS:
                return
            transition_case(
                case,
                "request_information",
                analyst,
                comment="Merci de préciser le navigateur utilisé.",
            )

    # ------------------------------------------------------------------ bounty
    def _bounty(self, cases, users):
        if len(cases) < 2:
            return
        case = cases[1]
        case.refresh_from_db()
        if getattr(case, "bounty", None) is not None:
            return
        if case.bounty_status != CaseBountyStatus.BOUNTY_ELIGIBLE:
            return
        bounty = propose_bounty(
            case,
            users["analyste@csirt.bf"],
            justification=(
                "Vulnérabilité IDOR permettant l'accès aux dossiers de tous les "
                "usagers. Impact élevé sur la confidentialité."
            ),
        )
        approve_bounty(
            bounty,
            users["coordinateur@anssi.bf"],
            note="Montant conforme au palier HIGH du programme.",
        )

    # ---------------------------------------------------------------- advisory
    def _advisory(self, cases, users):
        from apps.disclosures.models import Advisory

        if not cases:
            return
        case = cases[0]
        case.refresh_from_db()
        coordinator = users["coordinateur@anssi.bf"]
        analyst = users["analyste@csirt.bf"]
        if case.status == CaseStatus.ADVISORY_REVIEW:
            transition_case(case, "publish_and_close", coordinator, comment="Relecture faite.")
            return
        # Rejouable : rien a faire si le dossier n'attend pas son advisory
        # (deja clos, ou base v1 migree avec un advisory deja publie).
        if (
            case.status != CaseStatus.FIX_VERIFIED
            or Advisory.objects.filter(case=case).exclude(status="RETRACTED").exists()
        ):
            return
        # Etapes 9 et 10 : l'analyste redige et soumet, le Coordinateur relit
        # puis publie et clot (quatre yeux).
        create_advisory_from_case(
            case,
            analyst,
            summary=(
                "Une vulnérabilité d'injection SQL affectait le portail e-État civil "
                "du ministère de démonstration. Elle permettait à un attaquant non "
                "authentifié d'accéder à des données d'état civil. Un correctif à "
                "été deploye et verifie."
            ),
            description=(
                "Le paramètre de recherche du portail n'était pas correctement "
                "neutralise, autorisant l'injection de commandes SQL.\n\n"
                "Aucune exploitation malveillante n'a été constatee."
            ),
            impact=("Accès non autorisé en lecture aux données d'état civil des usagers."),
            solution=(
                "Appliquer la mise à jour du portail fournie par l'éditeur. Le "
                "correctif introduit des requêtes paramétrées et une validation "
                "stricte des entrees."
            ),
            affected_versions="Portail e-Etat civil < 2.4.1",
            fixed_versions="Portail e-Etat civil 2.4.1",
        )
        transition_case(case, "submit_advisory", analyst)
        transition_case(case, "publish_and_close", coordinator, comment="Relecture faite.")
