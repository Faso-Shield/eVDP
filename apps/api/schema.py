"""Extensions de schema OpenAPI propres a eVDP."""

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class ApiKeyAuthenticationScheme(OpenApiAuthenticationExtension):
    """Decrit l'authentification par cle d'API dans le schema publie."""

    target_class = "apps.api.authentication.ApiKeyAuthentication"
    name = "ApiKeyAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "header",
            "name": "X-eVDP-Api-Key",
            "description": (
                "Cle d'API eVDP. Seul son hachage SHA-256 est conserve par la "
                "plateforme : la valeur en clair n'est affichee qu'a la creation. "
                "Une cle peut etre revoquee ou expirer."
            ),
        }
