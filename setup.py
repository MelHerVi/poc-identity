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


def step5_setup_keystone_user():
    """Crea el usuario y proyecto en Keystone."""
    print("\n[5/8] Configurando usuario en Keystone...")
    # Obtener token de admin de Keystone
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
            "scope": {"project": {"name": "admin", "domain": {"name": "Default"}}},
        }
    }
    try:
        r = requests.post(f"{KEYSTONE_URL}/v3/auth/tokens", json=admin_auth)
        if r.status_code != 201:
            print(f"  Error autenticando en Keystone: {r.status_code}")
            return
        admin_token = r.headers.get("X-Subject-Token")
        ks_headers = {"X-Auth-Token": admin_token, "Content-Type": "application/json"}

        # Crear proyecto poc-project
        projects = requests.get(
            f"{KEYSTONE_URL}/v3/projects?name={KS_PROJECT}", headers=ks_headers
        ).json()
        if not projects.get("projects"):
            r = requests.post(
                f"{KEYSTONE_URL}/v3/projects",
                headers=ks_headers,
                json={
                    "project": {
                        "name": KS_PROJECT,
                        "domain_id": "default",
                        "enabled": True,
                    }
                },
            )
            project_id = r.json()["project"]["id"]
            print(f"  OK - Proyecto '{KS_PROJECT}' creado")
        else:
            project_id = projects["projects"][0]["id"]
            print(f"  Proyecto '{KS_PROJECT}' ya existe")

        # Crear usuario poc-user
        users = requests.get(
            f"{KEYSTONE_URL}/v3/users?name={KS_USER}", headers=ks_headers
        ).json()
        if not users.get("users"):
            r = requests.post(
                f"{KEYSTONE_URL}/v3/users",
                headers=ks_headers,
                json={
                    "user": {
                        "name": KS_USER,
                        "password": KS_PASS,
                        "domain_id": "default",
                        "enabled": True,
                    }
                },
            )
            user_id = r.json()["user"]["id"]
            print(f"  OK - Usuario '{KS_USER}' creado")
        else:
            user_id = users["users"][0]["id"]
            print(f"  Usuario '{KS_USER}' ya existe")

        # Asignar rol member al usuario en el proyecto
        roles = requests.get(
            f"{KEYSTONE_URL}/v3/roles?name=member", headers=ks_headers
        ).json()
        if roles.get("roles"):
            role_id = roles["roles"][0]["id"]
            requests.put(
                f"{KEYSTONE_URL}/v3/projects/{project_id}/users/{user_id}/roles/{role_id}",
                headers=ks_headers,
            )
            print(f"  OK - Rol 'member' asignado")

        return user_id
    except Exception as e:
        print(f"  Error: {e}")
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
    if any(l.get("identityProvider") == IDP_ALIAS for l in links):
        print("  Ya vinculado")
        return

    # Obtener el ID del usuario en Keystone
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
            "scope": {"project": {"name": "admin", "domain": {"name": "Default"}}},
        }
    }
    r = requests.post(f"{KEYSTONE_URL}/v3/auth/tokens", json=admin_auth)
    admin_token = r.headers.get("X-Subject-Token")
    ks_headers = {"X-Auth-Token": admin_token}

    ks_users = requests.get(
        f"{KEYSTONE_URL}/v3/users?name={KS_USER}", headers=ks_headers
    ).json()
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

    print("\n" + "=" * 70)
    print("  SETUP COMPLETADO")
    print("  Ahora puedes ejecutar: python demo.py")
    print("=" * 70)
