"""
DEMO FINAL - Flujo Real de Identidad Federada
=============================================
Keystone Token -> Keycloak Token Exchange -> JWT Firmado

Este script demuestra el intercambio REAL de tokens:
1. Obtiene un token Fernet de OpenStack Keystone
2. Envia ese token a Keycloak via Token Exchange (RFC 8693)
3. Keycloak valida el token contra Keystone (a traves del Adapter)
4. Keycloak devuelve un JWT firmado con los claims del usuario
"""

import requests
import json
import base64

import time

KEYSTONE_URL = "http://localhost:5000/v3"
KEYCLOAK_URL = "http://localhost:8080"
REALM = "cloud-orch"
CLIENT_ID = "orchestrator-client"
CLIENT_SECRET = "orchestrator-secret-2026"


def step1_get_keystone_token():
    """Obtener un token real de OpenStack Keystone (con reintentos)."""
    auth_data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": "poc-user",
                        "domain": {"name": "Default"},
                        "password": "password",
                    }
                },
            },
            "scope": {
                "project": {
                    "name": "poc-project",
                    "domain": {"name": "Default"},
                }
            },
        }
    }
    for i in range(10):
        try:
            r = requests.post(
                f"{KEYSTONE_URL}/auth/tokens",
                json=auth_data,
                timeout=10,
            )
            if r.status_code == 201:
                return r.headers.get("X-Subject-Token")
            print(f"  Keystone no listo (Status {r.status_code}), reintentando...")
        except Exception:
            print(f"  Keystone no responde (intento {i + 1}/10)...")
        time.sleep(5)
    return None


def step2_exchange_for_jwt(keystone_token):
    """
    Enviar el token de Keystone a Keycloak y recibir un JWT firmado.

    Este es el flujo real de Token Exchange (RFC 8693):
    - grant_type: urn:ietf:params:oauth:grant-type:token-exchange
    - subject_token: el token de Keystone
    - subject_issuer: el alias del IdP en Keycloak

    Keycloak internamente:
    1. Recibe el token de Keystone
    2. Llama al Keystone-Adapter (/introspect y /userinfo)
    3. El Adapter valida el token contra la API real de OpenStack
    4. Si es valido, Keycloak emite un JWT firmado con su propia clave
    """
    exchange_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "subject_token": keystone_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_issuer": "keystone-idp",
    }
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data=exchange_data,
    )
    data = r.json()
    if "access_token" in data:
        return data["access_token"]
    else:
        print(f"  Error en exchange: {data.get('error_description', data)}")
        return None


def decode_jwt(token):
    """Decodificar el payload de un JWT (sin verificar firma)."""
    payload = token.split(".")[1]
    # Padding
    decoded = base64.b64decode(payload + "==").decode("utf-8")
    return json.loads(decoded)


if __name__ == "__main__":
    print("=" * 70)
    print("  FLUJO DE IDENTIDAD FEDERADA: KEYSTONE -> KEYCLOAK -> JWT")
    print("=" * 70)

    # STEP 1: Token de Keystone
    print("\n[STEP 1] Autenticando en OpenStack Keystone...")
    ks_token = step1_get_keystone_token()
    if ks_token:
        print(f"  OK - Token Keystone: {ks_token[:40]}...")
    else:
        print("  ERROR - No se pudo obtener token de Keystone")
        exit(1)

    # STEP 2: Token Exchange real a Keycloak
    print("\n[STEP 2] Enviando token a Keycloak (Token Exchange RFC 8693)...")
    print("  -> Keycloak llama al Adapter para validar contra Keystone...")
    jwt = step2_exchange_for_jwt(ks_token)
    if jwt:
        print("  OK - Keycloak ha emitido un JWT firmado")
    else:
        print("  ERROR - El intercambio fallo")
        exit(1)

    # STEP 3: Analizar el JWT
    print("\n[STEP 3] Analizando el JWT recibido:")
    claims = decode_jwt(jwt)
    print("-" * 70)
    print(f"  Usuario:  {claims.get('preferred_username')}")
    print(f"  Sub UUID: {claims.get('sub')}")
    print(f"  Emisor:   {claims.get('iss')}")
    print(f"  Scopes:   {claims.get('scope')}")
    print(f"  Tipo:     {claims.get('typ')}")
    print(f"  AZP:      {claims.get('azp')}")
    # Claims personalizados de Keystone
    ks_uid = claims.get("keystone_user_id")
    ks_pid = claims.get("keystone_project_id")
    ks_pname = claims.get("keystone_project_name")
    ks_roles = claims.get("keystone_roles")
    if ks_uid or ks_pid:
        print("  --- Claims de Keystone ---")
        print(f"  KS User ID:     {ks_uid}")
        print(f"  KS Project ID:  {ks_pid}")
        print(f"  KS Project:     {ks_pname}")
        print(f"  KS Roles:       {ks_roles}")
    print("-" * 70)

    print("\n[JWT Token]")
    print(jwt)

    print("\n" + "=" * 70)
    print("  PRUEBA DE CONCEPTO COMPLETADA CON EXITO")
    print("  El token JWT puede usarse con cualquier aplicacion que")
    print("  confie en Keycloak como Identity Provider (ej: Commvault)")
    print("=" * 70)
