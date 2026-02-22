"""
==============================================================================
  SETUP INICIAL - Ejecutar UNA SOLA VEZ despues de 'docker-compose up -d'
==============================================================================

Este script configura TODO lo necesario en Keycloak y Keystone para que
el flujo de Token Exchange funcione. Solo hay que ejecutarlo una vez.

Prerequisitos:
  1. docker-compose up -d (y esperar ~30s a que arranquen los servicios)
  2. python -m pip install requests (si no esta instalado)

Uso:
  python setup.py
"""

import requests
import time
import sys

# =============================================================================
# CONFIGURACION
# =============================================================================
KEYCLOAK_URL = "http://localhost:8080"
KEYSTONE_URL = "http://localhost:5000"
REALM = "cloud-orch"
CLIENT_ID = "orchestrator-client"
CLIENT_SECRET = "orchestrator-secret-2026"
ADAPTER_BASE = "http://keystone-adapter:8000"
IDP_ALIAS = "keystone-idp"

# Credenciales de Keystone para el usuario de prueba
KS_USER = "poc-user"
KS_PASS = "password"
KS_PROJECT = "poc-project"


def wait_for_services():
    """Espera a que Keycloak y Keystone esten disponibles."""
    print("=" * 70)
    print("  SETUP INICIAL - Configuracion automatica del entorno")
    print("=" * 70)
    print("\n[0/8] Esperando a que los servicios arranquen...")

    for name, url in [("Keycloak", KEYCLOAK_URL), ("Keystone", f"{KEYSTONE_URL}/v3")]:
        for i in range(30):
            try:
                r = requests.get(url, timeout=3)
                if r.status_code < 500:
                    print(f"  OK - {name} disponible")
                    break
            except Exception:
                pass
            if i == 29:
                print(f"  ERROR - {name} no responde en {url}")
                sys.exit(1)
            time.sleep(2)


def get_admin_token():
    """Obtiene token de admin de Keycloak."""
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
        },
    )
    return r.json()["access_token"]


def step1_create_realm(headers):
    """Crea el realm cloud-orch."""
    print("\n[1/8] Creando realm 'cloud-orch'...")
    # Verificar si ya existe
    r = requests.get(f"{KEYCLOAK_URL}/admin/realms/{REALM}", headers=headers)
    if r.status_code == 200:
        print("  Ya existe, actualizando SSL...")
        realm = r.json()
        realm["sslRequired"] = "none"
        requests.put(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}", headers=headers, json=realm
        )
        return

    realm_data = {
        "realm": REALM,
        "enabled": True,
        "sslRequired": "none",
        "registrationAllowed": False,
        "loginWithEmailAllowed": False,
        "duplicateEmailsAllowed": True,
    }
    r = requests.post(f"{KEYCLOAK_URL}/admin/realms", headers=headers, json=realm_data)
    if r.status_code == 201:
        print("  OK - Realm creado")
    else:
        print(f"  Error: {r.status_code} {r.text[:200]}")
        sys.exit(1)


def step2_create_client(headers):
    """Crea el cliente orchestrator-client."""
    print("\n[2/8] Creando cliente 'orchestrator-client'...")
    # Verificar si ya existe
    existing = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={CLIENT_ID}",
        headers=headers,
    ).json()
    if existing:
        print("  Ya existe, actualizando...")
        client = existing[0]
        client["attributes"]["standard.token.exchange.enabled"] = "true"
        requests.put(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client['id']}",
            headers=headers,
            json=client,
        )
        return

    client_data = {
        "clientId": CLIENT_ID,
        "secret": CLIENT_SECRET,
        "enabled": True,
        "publicClient": False,
        "serviceAccountsEnabled": True,
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled": True,
        "attributes": {"standard.token.exchange.enabled": "true"},
    }
    r = requests.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
        headers=headers,
        json=client_data,
    )
    if r.status_code == 201:
        print("  OK - Cliente creado")
    else:
        print(f"  Error: {r.status_code} {r.text[:200]}")


def step3_create_idp(headers):
    """Crea el Identity Provider keystone-idp."""
    print("\n[3/8] Creando Identity Provider 'keystone-idp'...")
    # Verificar si ya existe
    r = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances/{IDP_ALIAS}",
        headers=headers,
    )
    if r.status_code == 200:
        print("  Ya existe, actualizando...")
        idp = r.json()
        idp["config"]["userInfoUrl"] = f"{ADAPTER_BASE}/userinfo"
        idp["config"]["tokenExchangeSupported"] = "true"
        idp.pop("internalId", None)
        requests.put(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances/{IDP_ALIAS}",
            headers=headers,
            json=idp,
        )
        return

    idp_data = {
        "alias": IDP_ALIAS,
        "displayName": "OpenStack Keystone",
        "providerId": "oidc",
        "enabled": True,
        "trustEmail": True,
        "config": {
            "clientId": "keycloak-id",
            "clientSecret": "keycloak-secret-2026",
            "clientAuthMethod": "client_secret_post",
            "useDiscoveryEndpoint": "true",
            "discoveryEndpoint": f"{ADAPTER_BASE}/.well-known/openid-configuration",
            "tokenUrl": "http://keystone:5000/v3/auth/tokens",
            "authorizationUrl": "http://localhost:5000/v3/auth/OS-FEDERATION/websso/openid/protocol/openid/auth",
            "introspectionUrl": f"{ADAPTER_BASE}/introspect",
            "tokenIntrospectionUrl": f"{ADAPTER_BASE}/introspect",
            "userInfoUrl": f"{ADAPTER_BASE}/userinfo",
            "issuer": "http://keystone:5000/v3",
            "validateSignature": "false",
            "isAccessTokenJWT": "false",
            "syncMode": "IMPORT",
            "tokenExchangeSupported": "true",
            "disableUserInfo": "false",
        },
    }
    r = requests.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances",
        headers=headers,
        json=idp_data,
    )
    if r.status_code == 201:
        print("  OK - Identity Provider creado")
    else:
        print(f"  Error: {r.status_code} {r.text[:200]}")


def step4_create_keycloak_user(headers):
    """Crea el usuario poc-user en Keycloak."""
    print("\n[4/8] Creando usuario 'poc-user' en Keycloak...")
    existing = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?username={KS_USER}",
        headers=headers,
    ).json()
    if existing:
        print("  Ya existe")
        return existing[0]["id"]

    user_data = {
        "username": KS_USER,
        "enabled": True,
        "emailVerified": True,
        "credentials": [{"type": "password", "value": KS_PASS, "temporary": False}],
    }
    r = requests.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
        headers=headers,
        json=user_data,
    )
    if r.status_code == 201:
        user_id = r.headers.get("Location", "").split("/")[-1]
        print(f"  OK - Usuario creado (ID: {user_id})")
        return user_id
    else:
        print(f"  Error: {r.status_code} {r.text[:200]}")
        return None


def get_keystone_token():
    """
    Obtiene un token de admin de Keystone con reintentos.
    Espera a que Keystone termine su bootstrap interno.
    """
    admin_auth = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": "admin",
                        "domain": {"name": "Default"},
                        "password": "password",
                    }
                },
            },
            "scope": {
                "project": {
                    "name": "admin",
                    "domain": {"name": "Default"},
                }
            },
        }
    }
    for i in range(20):
        try:
            r = requests.post(
                f"{KEYSTONE_URL}/v3/auth/tokens",
                json=admin_auth,
                timeout=10,
            )
            if r.status_code == 201:
                return r.headers.get("X-Subject-Token")
            print(f"  Keystone no listo (Status {r.status_code}), reintentando...")
        except Exception:
            print(f"  Keystone no responde (intento {i + 1}/20)...")
        time.sleep(5)
    return None


def ks_request(method, path, token, **kwargs):
    """
    Ejecuta una peticion a Keystone con reintentos automaticos.
    Maneja errores 500 transitorios durante el arranque.
    """
    url = f"{KEYSTONE_URL}/v3{path}"
    headers = {
        "X-Auth-Token": token,
        "Content-Type": "application/json",
    }
    for attempt in range(12):
        try:
            r = requests.request(method, url, headers=headers, timeout=10, **kwargs)
            if r.status_code >= 500:
                print(
                    f"  Keystone error {r.status_code}, reintentando ({attempt + 1}/12)..."
                )
                time.sleep(5)
                continue
            # Para PUT que no devuelve body (ej: asignar rol)
            if r.status_code == 204 or not r.text:
                return {"_status": r.status_code}
            return r.json()
        except requests.exceptions.ConnectionError:
            print(f"  Keystone no accesible, reintentando ({attempt + 1}/12)...")
            time.sleep(5)
    raise RuntimeError(f"Keystone no respondio tras 12 intentos en {path}")


def step5_setup_keystone_user():
    """
    Crea el usuario y proyecto en Keystone.
    Usa ks_request() para reintentar automaticamente si Keystone
    devuelve errores 500 transitorios durante el arranque.
    """
    print("\n[5/8] Configurando usuario en Keystone...")

    token = get_keystone_token()
    if not token:
        print("  Error: Keystone no acepto credenciales admin.")
        return None

    try:
        # 1. Proyecto
        data = ks_request("GET", f"/projects?name={KS_PROJECT}", token)
        if not data.get("projects"):
            resp = ks_request(
                "POST",
                "/projects",
                token,
                json={
                    "project": {
                        "name": KS_PROJECT,
                        "domain_id": "default",
                        "enabled": True,
                    }
                },
            )
            project_id = resp["project"]["id"]
            print(f"  OK - Proyecto '{KS_PROJECT}' creado")
        else:
            project_id = data["projects"][0]["id"]
            print(f"  Proyecto '{KS_PROJECT}' ya existe")

        # 2. Usuario
        data = ks_request("GET", f"/users?name={KS_USER}", token)
        if not data.get("users"):
            resp = ks_request(
                "POST",
                "/users",
                token,
                json={
                    "user": {
                        "name": KS_USER,
                        "password": KS_PASS,
                        "domain_id": "default",
                        "enabled": True,
                    }
                },
            )
            user_id = resp["user"]["id"]
            print(f"  OK - Usuario '{KS_USER}' creado")
        else:
            user_id = data["users"][0]["id"]
            print(f"  Usuario '{KS_USER}' ya existe")

        # 3. Rol member
        data = ks_request("GET", "/roles?name=member", token)
        if data.get("roles"):
            role_id = data["roles"][0]["id"]
            ks_request(
                "PUT",
                f"/projects/{project_id}/users/{user_id}/roles/{role_id}",
                token,
            )
            print("  OK - Rol 'member' asignado")

        return user_id
    except Exception as e:
        print(f"  Error en Step 5: {e}")
        return None


def step6_enable_permissions(headers):
    """Habilita los permisos fine-grained en el IdP y el cliente."""
    print("\n[6/8] Habilitando permisos fine-grained...")

    # Habilitar permisos del IdP
    r = requests.put(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances/{IDP_ALIAS}/management/permissions",
        headers=headers,
        json={"enabled": True},
    )
    idp_perms = r.json()
    print(
        f"  OK - IdP permissions: {idp_perms.get('scopePermissions', {}).get('token-exchange', 'N/A')}"
    )

    # Habilitar permisos del cliente
    orch = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={CLIENT_ID}",
        headers=headers,
    ).json()
    orch_id = orch[0]["id"]
    r = requests.put(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{orch_id}/management/permissions",
        headers=headers,
        json={"enabled": True},
    )
    print(f"  OK - Client permissions habilitados")

    return orch_id


def step7_create_policies(headers):
    """Crea las politicas y vincula a los permisos de token-exchange."""
    print("\n[7/8] Configurando politicas de autorizacion...")

    rm = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId=realm-management",
        headers=headers,
    ).json()
    rm_id = rm[0]["id"]

    # Crear politica de tipo 'role' con el rol por defecto
    roles = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles", headers=headers
    ).json()
    default_role = next(r for r in roles if "default" in r["name"].lower())

    # Verificar si ya existe
    policies = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{rm_id}/authz/resource-server/policy",
        headers=headers,
    ).json()
    role_policy = next((p for p in policies if p["type"] == "role"), None)

    if not role_policy:
        pr = requests.post(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{rm_id}/authz/resource-server/policy/role",
            headers=headers,
            json={
                "name": "allow-all",
                "type": "role",
                "logic": "POSITIVE",
                "roles": [{"id": default_role["id"], "required": False}],
            },
        )
        role_policy = pr.json()
        print(f"  OK - Politica 'allow-all' creada")
    else:
        print(f"  Politica ya existe: {role_policy['name']}")

    # Vincular politica a TODOS los permisos que contengan 'token-exchange'
    scopes = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{rm_id}/authz/resource-server/scope",
        headers=headers,
    ).json()
    exchange_scope = next(s for s in scopes if s["name"] == "token-exchange")

    resources = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{rm_id}/authz/resource-server/resource",
        headers=headers,
    ).json()

    perms = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{rm_id}/authz/resource-server/permission",
        headers=headers,
    ).json()

    for p in perms:
        res_id = None
        for r in resources:
            for part in r["_id"].split("-"):
                if len(part) > 4 and part in p["name"]:
                    res_id = r["_id"]
                    break
            if res_id:
                break

        update = {
            "id": p["id"],
            "name": p["name"],
            "type": "scope",
            "logic": "POSITIVE",
            "decisionStrategy": "AFFIRMATIVE",
            "scopes": [exchange_scope["id"]],
            "policies": [role_policy["id"]],
        }
        if res_id:
            update["resources"] = [res_id]

        requests.put(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{rm_id}/authz/resource-server/permission/scope/{p['id']}",
            headers=headers,
            json=update,
        )

    # Crear permiso token-exchange del cliente si no existe
    orch = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={CLIENT_ID}",
        headers=headers,
    ).json()
    orch_uuid = orch[0]["id"]

    client_te = next(
        (p for p in perms if "token-exchange" in p["name"] and orch_uuid in p["name"]),
        None,
    )
    if not client_te:
        client_res = next((r for r in resources if orch_uuid in r["name"]), None)
        new_perm = {
            "name": f"token-exchange.permission.client.{orch_uuid}",
            "type": "scope",
            "logic": "POSITIVE",
            "decisionStrategy": "AFFIRMATIVE",
            "scopes": [exchange_scope["id"]],
            "policies": [role_policy["id"]],
        }
        if client_res:
            new_perm["resources"] = [client_res["_id"]]
        requests.post(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{rm_id}/authz/resource-server/permission/scope",
            headers=headers,
            json=new_perm,
        )
        print(f"  OK - Permiso token-exchange del cliente creado")

    print("  OK - Politicas vinculadas a todos los permisos")


def step8_link_user(headers):
    """Vincula el usuario de Keycloak con el IdP de Keystone."""
    print("\n[8/8] Vinculando usuario con Keystone IdP...")

    users = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?username={KS_USER}",
        headers=headers,
    ).json()
    if not users:
        print("  ERROR - Usuario no encontrado en Keycloak")
        return
    user_id = users[0]["id"]

    # Verificar si ya tiene link
    links = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/federated-identity",
        headers=headers,
    ).json()
    if any(link.get("identityProvider") == IDP_ALIAS for link in links):
        print("  Ya vinculado")
        return

    # Obtener el ID del usuario en Keystone (con reintentos)
    ks_token = get_keystone_token()
    if not ks_token:
        print("  Error: No se pudo autenticar en Keystone")
        return

    ks_users = ks_request("GET", f"/users?name={KS_USER}", ks_token)
    if not ks_users.get("users"):
        print(f"  Error: No se encontro el usuario {KS_USER} en Keystone")
        return

    ks_user_id = ks_users["users"][0]["id"]

    # Crear el link federado
    link_data = {
        "identityProvider": IDP_ALIAS,
        "userId": ks_user_id,
        "userName": KS_USER,
    }
    r = requests.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/federated-identity/{IDP_ALIAS}",
        headers=headers,
        json=link_data,
    )
    if r.status_code == 204:
        print(f"  OK - Usuario vinculado (Keystone ID: {ks_user_id})")
    else:
        print(f"  Error: {r.status_code} {r.text[:200]}")


def step9_create_mappers(headers):
    """Crea mappers para inyectar datos de Keystone en el JWT."""
    print("\n[9/9] Creando mappers de claims...")

    # --- 1. IdP Mappers: importar claims del userinfo
    #         como atributos del usuario en Keycloak ---
    idp_claims = [
        ("keystone_user_id", "keystone_user_id"),
        ("keystone_project_id", "keystone_project_id"),
        ("keystone_project_name", "keystone_project_name"),
        ("keystone_roles", "keystone_roles"),
    ]

    idp_url = (
        f"{KEYCLOAK_URL}/admin/realms/{REALM}"
        f"/identity-provider/instances/{IDP_ALIAS}/mappers"
    )

    # Obtener mappers existentes
    existing = requests.get(idp_url, headers=headers).json()
    existing_names = [m.get("name") for m in existing]

    for claim, attr in idp_claims:
        name = f"ks-{claim}"
        if name in existing_names:
            print(f"  Mapper IdP '{name}' ya existe")
            continue
        mapper = {
            "name": name,
            "identityProviderAlias": IDP_ALIAS,
            "identityProviderMapper": ("oidc-user-attribute-idp-mapper"),
            "config": {
                "syncMode": "INHERIT",
                "claim": claim,
                "user.attribute": attr,
            },
        }
        r = requests.post(idp_url, headers=headers, json=mapper)
        if r.status_code == 201:
            print(f"  OK - Mapper IdP '{name}' creado")
        else:
            print(f"  WARN - Mapper IdP '{name}': {r.status_code}")

    # --- 2. Client Protocol Mappers: inyectar atributos
    #         del usuario en el JWT ---
    # Buscar el client ID interno
    clients = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}" f"/clients?clientId={CLIENT_ID}",
        headers=headers,
    ).json()
    if not clients:
        print("  Error: Cliente no encontrado")
        return
    client_uuid = clients[0]["id"]

    client_url = (
        f"{KEYCLOAK_URL}/admin/realms/{REALM}"
        f"/clients/{client_uuid}/protocol-mappers/models"
    )

    # Obtener mappers existentes del cliente
    existing_client = requests.get(client_url, headers=headers).json()
    existing_client_names = [m.get("name") for m in existing_client]

    jwt_claims = [
        ("keystone_user_id", "String"),
        ("keystone_project_id", "String"),
        ("keystone_project_name", "String"),
        ("keystone_roles", "String"),
    ]

    for attr, json_type in jwt_claims:
        name = f"ks-{attr}"
        if name in existing_client_names:
            print(f"  Mapper JWT '{name}' ya existe")
            continue
        mapper = {
            "name": name,
            "protocol": "openid-connect",
            "protocolMapper": ("oidc-usermodel-attribute-mapper"),
            "config": {
                "user.attribute": attr,
                "claim.name": attr,
                "jsonType.label": json_type,
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        }
        r = requests.post(client_url, headers=headers, json=mapper)
        if r.status_code == 201:
            print(f"  OK - Mapper JWT '{name}' creado")
        else:
            print(f"  WARN - Mapper JWT '{name}': {r.status_code}")


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    wait_for_services()

    token = get_admin_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    step1_create_realm(headers)
    step2_create_client(headers)
    step3_create_idp(headers)
    step4_create_keycloak_user(headers)
    step5_setup_keystone_user()
    step6_enable_permissions(headers)
    step7_create_policies(headers)
    step8_link_user(headers)
    step9_create_mappers(headers)

    print("\n" + "=" * 70)
    print("  SETUP COMPLETADO")
    print("  Ahora puedes ejecutar: python demo.py")
    print("=" * 70)
