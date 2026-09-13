"""Taxonomies partagees : severite et types de vulnerabilites."""

from django.db import models


class Severity(models.TextChoices):
    CRITICAL = "CRITICAL", "Critique"
    HIGH = "HIGH", "Élevée"
    MEDIUM = "MEDIUM", "Moyenne"
    LOW = "LOW", "Faible"
    INFO = "INFO", "Informative"

    @classmethod
    def from_score(cls, score):
        """Conversion CVSS v3.1 -> severite qualitative."""
        if score is None:
            return cls.INFO
        score = float(score)
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO

    @classmethod
    def rank(cls, value):
        order = {cls.INFO: 0, cls.LOW: 1, cls.MEDIUM: 2, cls.HIGH: 3, cls.CRITICAL: 4}
        return order.get(value, 0)


class VulnerabilityType(models.TextChoices):
    AUTHENTICATION = "AUTHENTICATION", "Authentification"
    AUTHORIZATION = "AUTHORIZATION", "Autorisation / contrôle d'accès"
    XSS = "XSS", "Cross-Site Scripting (XSS)"
    SQLI = "SQLI", "Injection SQL"
    SSRF = "SSRF", "Server-Side Request Forgery (SSRF)"
    RCE = "RCE", "Exécution de code à distance (RCE)"
    LFI_RFI = "LFI_RFI", "Inclusion de fichier (LFI/RFI)"
    IDOR = "IDOR", "Référence directe non sécurisée (IDOR)"
    CSRF = "CSRF", "Cross-Site Request Forgery (CSRF)"
    INFO_DISCLOSURE = "INFO_DISCLOSURE", "Divulgation d'information"
    MISCONFIGURATION = "MISCONFIGURATION", "Mauvaise configuration"
    CRYPTO = "CRYPTO", "Problème cryptographique"
    BUSINESS_LOGIC = "BUSINESS_LOGIC", "Logique métier"
    API_SECURITY = "API_SECURITY", "Sécurité des API"
    MOBILE = "MOBILE", "Application mobile"
    CLOUD = "CLOUD", "Cloud"
    NETWORK = "NETWORK", "Réseau / infrastructure"
    OTHER = "OTHER", "Autre"


#: Correspondance indicative type de vulnerabilite -> CWE le plus courant.
TYPE_TO_CWE = {
    VulnerabilityType.AUTHENTICATION: "CWE-287",
    VulnerabilityType.AUTHORIZATION: "CWE-285",
    VulnerabilityType.XSS: "CWE-79",
    VulnerabilityType.SQLI: "CWE-89",
    VulnerabilityType.SSRF: "CWE-918",
    VulnerabilityType.RCE: "CWE-94",
    VulnerabilityType.LFI_RFI: "CWE-98",
    VulnerabilityType.IDOR: "CWE-639",
    VulnerabilityType.CSRF: "CWE-352",
    VulnerabilityType.INFO_DISCLOSURE: "CWE-200",
    VulnerabilityType.MISCONFIGURATION: "CWE-16",
    VulnerabilityType.CRYPTO: "CWE-327",
    VulnerabilityType.BUSINESS_LOGIC: "CWE-840",
    VulnerabilityType.API_SECURITY: "CWE-1059",
    VulnerabilityType.MOBILE: "CWE-919",
    VulnerabilityType.CLOUD: "CWE-1188",
    VulnerabilityType.NETWORK: "CWE-923",
}


class ReportSource(models.TextChoices):
    WEB = "WEB", "Formulaire web"
    API = "API", "API"
    EMAIL = "EMAIL", "Email"
    CSAF = "CSAF", "Import CSAF"
    INTERNAL = "INTERNAL", "Interne"
