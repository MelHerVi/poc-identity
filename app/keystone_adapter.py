from flask import Flask, request, jsonify
import requests
import datetime
import time

app = Flask(__name__)

KEYSTONE_URL = "http://keystone:5000/v3"


def get_admin_token():
    """Obtiene un token de administrador para validar otros tokens."""
    auth_data = {
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
        r = requests.post(f"{KEYSTONE_URL}/auth/tokens", json=auth_data)
        return r.headers.get("X-Subject-Token")
    except Exception as e:
        print(f"Error obteniendo token de admin: {e}")
        return None


@app.route("/introspect", methods=["POST"])
def introspect():
    # El token que Keycloak nos envía para validar
    token_to_validate = request.form.get("token")

    if not token_to_validate:
        return jsonify({"active": False}), 400

    admin_token = get_admin_token()
    if not admin_token:
        return jsonify({"active": False, "error": "Keystone unavailable"}), 500

    # VALIDACIÓN REAL CONTRA KEYSTONE
    # Usamos el token de admin para validar el token que recibimos (X-Subject-Token)
    headers = {"X-Auth-Token": admin_token, "X-Subject-Token": token_to_validate}

    try:
        r = requests.get(f"{KEYSTONE_URL}/auth/tokens", headers=headers)

        if r.status_code == 200:
            data = r.json().get("token", {})
            user = data.get("user", {})

            # Convertir la fecha de expiración de Keystone a timestamp
            exp_str = data.get("expires_at")
            # Ejemplo Keystone: 2026-02-21T16:15:42.000000Z
            exp_dt = datetime.datetime.strptime(exp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            exp_ts = int(time.mktime(exp_dt.timetuple()))

            # Respuesta RFC 7662 Real
            response_data = {
                "active": True,
                "username": user.get("name"),
                "exp": exp_ts,
                "sub": user.get("id"),
                "iss": KEYSTONE_URL,
                "client_id": "orchestrator-client",
            }
            return jsonify(response_data)
        else:
            print(f"Token inválido en Keystone (Status {r.status_code})")
            return jsonify({"active": False})

    except Exception as e:
        print(f"Error validando contra Keystone: {e}")
        return jsonify({"active": False}), 500


@app.route("/userinfo", methods=["GET", "POST"])
def userinfo():
    """Valida el token y devuelve la información real del usuario."""
    # Keycloak envía el token como Bearer en el header Authorization
    auth_header = request.headers.get("Authorization", "")
    token_to_validate = None

    if auth_header.startswith("Bearer "):
        token_to_validate = auth_header[7:]
    elif request.form.get("access_token"):
        token_to_validate = request.form.get("access_token")

    if not token_to_validate:
        return jsonify({"error": "no token provided"}), 401

    admin_token = get_admin_token()
    if not admin_token:
        return jsonify({"error": "Keystone unavailable"}), 500

    headers = {"X-Auth-Token": admin_token, "X-Subject-Token": token_to_validate}
    try:
        r = requests.get(f"{KEYSTONE_URL}/auth/tokens", headers=headers)
        if r.status_code == 200:
            data = r.json().get("token", {})
            user = data.get("user", {})
            return jsonify(
                {
                    "sub": user.get("id"),
                    "preferred_username": user.get("name"),
                    "email": f"{user.get('name', 'user')}@openstack.local",
                    "name": user.get("name"),
                    "domain": user.get("domain", {}).get("name", "Default"),
                }
            )
        else:
            return jsonify({"error": "invalid_token"}), 401
    except Exception as e:
        print(f"Error en userinfo: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/.well-known/openid-configuration", methods=["GET"])
def discovery():
    """Endpoint de auto-descubrimiento para Keycloak."""
    base = "http://keystone-adapter:8000"
    return jsonify(
        {
            "issuer": "http://keystone:5000/v3",
            "token_endpoint": "http://keystone:5000/v3/auth/tokens",
            "userinfo_endpoint": f"{base}/userinfo",
            "introspection_endpoint": f"{base}/introspect",
            "jwks_uri": f"{base}/jwks",
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
    )


@app.route("/jwks", methods=["GET"])
def jwks():
    """Simula un endpoint de llaves (necesario para el descubrimiento)."""
    return jsonify({"keys": []})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
