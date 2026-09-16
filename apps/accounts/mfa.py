"""Authentification a deux facteurs (TOTP, RFC 6238).

Le secret est stocke en clair en base (pratique standard pour TOTP, au meme
titre que la plupart des implementations de reference) ; seule sa lecture est
sensible, jamais transmise au navigateur apres l'ecran d'activation initial.
"""

import base64
import io

import pyotp
import qrcode

ISSUER = "eVDP"


def generate_secret():
    """Nouveau secret TOTP, encode en base32 (format standard)."""
    return pyotp.random_base32()


def provisioning_uri(email, secret):
    """URI otpauth:// a encoder en QR code pour l'application d'authentification."""
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def verify_code(secret, code):
    """Verifie un code a 6 chiffres, avec une tolerance d'une fenetre de 30s
    (horloge du telephone legerement en avance ou en retard)."""
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def qr_code_data_uri(uri):
    """PNG encode en data: URI - jamais ecrit sur disque ni servi par une URL."""
    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
