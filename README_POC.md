# POC: Identity Bridge - Keystone to Keycloak Token Exchange

## Resumen

Esta prueba de concepto demuestra un flujo real de **federacion de identidad** entre
**OpenStack Keystone** y **Keycloak**, donde un token Fernet de Keystone se intercambia
por un JWT firmado por Keycloak usando el estandar **RFC 8693 (Token Exchange)**.

## Arquitectura

```
  OpenStack Keystone          Identity Bridge           Keycloak
  (Token Fernet)           (keystone_adapter.py)       (JWT firmado)
       |                         |                        |
       |   1. Login              |                        |
       |<--- Token Fernet        |                        |
       |                         |                        |
       |                         |   2. Token Exchange     |
       |                         |   (subject_token=Fernet)|
       |                         |                        |
       |   3. Introspect ------->|                        |
       |   4. UserInfo --------->|                        |
       |                         |<------ Valida contra   |
       |                         |        Keystone API    |
       |                         |                        |
       |                         |   5. JWT Firmado ------>|
```

### Componentes

| Componente           | Tecnologia         | Funcion                                           |
| -------------------- | ------------------ | ------------------------------------------------- |
| **Keystone**         | OpenStack Identity | Emite tokens Fernet, fuente de identidad          |
| **Keystone Adapter** | Python/Flask       | Traduce tokens Keystone a formato OIDC (RFC 7662) |
| **Keycloak**         | v26.5 (Quarkus)    | Identity Broker, emite JWT firmados               |

### Por que se necesita el Adapter (introspection)

Keystone y Keycloak "hablan idiomas diferentes". Keycloak solo entiende protocolos
estandar (OIDC, OAuth 2.0), pero Keystone usa una API propietaria de OpenStack:

|                       | Keystone (OpenStack)                               | Keycloak (OIDC)                  |
| --------------------- | -------------------------------------------------- | -------------------------------- |
| **Formato del token** | Fernet (binario, opaco)                            | JWT (JSON, autocontenido)        |
| **Como se valida**    | `GET /v3/auth/tokens` con header `X-Subject-Token` | Verificando la firma RSA del JWT |
| **Estandar**          | API propietaria de OpenStack                       | OAuth 2.0 / OpenID Connect       |

Cuando Keycloak recibe un token externo para hacer token exchange, necesita verificar
que es valido. Pero no sabe "hablar OpenStack", asi que consulta dos endpoints estandar:

1. **Introspection** (RFC 7662): "Este token, es valido?" → `POST /introspect`
2. **UserInfo** (OIDC Core): "Quien es el usuario?" → `GET /userinfo`

El adapter **traduce** estas llamadas estandar a la API de Keystone:

```
Keycloak (OIDC)                Adapter                    Keystone (OpenStack)
──────────────               ──────────                 ────────────────────

POST /introspect    ──►     GET /v3/auth/tokens
  token=gAAAAA...            X-Subject-Token: gAAAAA...
                   ◄──
  { active: true,           { token: { user: {
    username: "poc",            name: "poc",
    sub: "f182..." }            id: "f182..." } } }


GET /userinfo       ──►     GET /v3/auth/tokens
  Bearer: gAAAAA...          X-Subject-Token: gAAAAA...
                   ◄──
  { sub: "f182...",          { token: { user: {
    name: "poc-user",           name: "poc-user",
    email: "..." }              domain: "Default" } } }
```

> **Nota**: Si Keystone fuera un proveedor OIDC nativo (como Azure AD, Google u Okta),
> no se necesitaria el adapter — Keycloak conectaria directamente.

### Estandares utilizados

| Estandar                | RFC/Spec            | Uso en esta POC                                   |
| ----------------------- | ------------------- | ------------------------------------------------- |
| **Token Introspection** | RFC 7662            | Adapter expone `/introspect` para validar tokens  |
| **UserInfo**            | OpenID Connect Core | Adapter expone `/userinfo` para datos del usuario |
| **Token Exchange**      | RFC 8693            | Keycloak intercambia token Keystone por JWT       |
| **JWT**                 | RFC 7519            | Formato del token final que emite Keycloak        |

## Configuracion de Keycloak

### Features Habilitadas

```yaml
command: start-dev --features=token-exchange,admin-fine-grained-authz:v1
```

- `token-exchange`: Habilita el flujo de Token Exchange (preview v1)
- `admin-fine-grained-authz:v1`: Permisos granulares para IdP (v1 porque v2 no soporta IdP)

### Configuracion Requerida

1. **Identity Provider** (`keystone-idp`):
   - Tipo: OpenID Connect v1.0
   - Discovery URL: `http://keystone-adapter:8000/.well-known/openid-configuration`
   - Introspection URL: `http://keystone-adapter:8000/introspect`
   - User Info URL: `http://keystone-adapter:8000/userinfo`
   - SSL del realm desactivado (desarrollo)
   - `tokenExchangeSupported: true`

2. **Client** (`orchestrator-client`):
   - Confidential client con service account habilitado
   - `standard.token.exchange.enabled: true`
   - Permissions habilitados (fine-grained)

3. **Permisos** (configurados via REST API):
   - Permiso `token-exchange` en el **IdP** con politica de role
   - Permiso `token-exchange` en el **Cliente** con la misma politica
   - Politica de tipo "role" usando `default-roles-cloud-orch`

4. **Federated Identity Link**:
   - El usuario local `poc-user` debe estar vinculado al IdP `keystone-idp`
   - El `userId` del link debe coincidir con el ID del usuario en Keystone

## Desafios Superados

### 1. UI de Keycloak 26 incompleta

La interfaz web de Keycloak 26 no muestra las opciones de "Permissions" para IdPs.
**Solucion**: Configuracion 100% via REST API del Admin.

### 2. FGAP v2 incompatible con Token Exchange de IdP

La version v2 de Fine-Grained Admin Permissions no soporta permisos de IdP.
**Solucion**: Forzar `admin-fine-grained-authz:v1`.

### 3. Tipo de politica incorrecta

Las politicas de tipo "client" no funcionan correctamente para token exchange.
**Solucion**: Usar politica de tipo "role" con el rol por defecto del realm.

### 4. "User already exists"

El token exchange intenta crear el usuario si no existe un link federado.
**Solucion**: Crear previamente el link entre el usuario local y el IdP.

### 5. Adapter colisionando con modulos Python

El archivo `inspect.py` colisionaba con el modulo estandar `inspect` de Python.
**Solucion**: Eliminar scripts de diagnostico del directorio `/app/`.

## Como Ejecutar

### Prerequisitos

- Docker y Docker Compose instalados
- Python 3.x con `requests` (`pip install requests`)

### Instalacion (3 comandos)

```bash
# 1. Levantar los servicios (Keystone, Keycloak, Adapter)
docker-compose up -d

# 2. Esperar ~30s y ejecutar el setup automatico (una sola vez)
python setup.py

# 3. Ejecutar la demo del flujo completo
python demo.py
```

### Que hace `setup.py`

El script de setup configura automaticamente:

| Paso | Componente | Que hace                                                           | Comando equivalente manual                               |
| ---- | ---------- | ------------------------------------------------------------------ | -------------------------------------------------------- |
| 1/8  | Keycloak   | Crear realm `cloud-orch` con SSL desactivado                       | `POST /admin/realms`                                     |
| 2/8  | Keycloak   | Crear client `orchestrator-client` (confidential, service account) | `POST /admin/realms/{realm}/clients`                     |
| 3/8  | Keycloak   | Crear IdP `keystone-idp` apuntando al adapter                      | `POST /admin/realms/{realm}/identity-provider/instances` |
| 4/8  | Keycloak   | Crear usuario `poc-user`                                           | `POST /admin/realms/{realm}/users`                       |
| 5/8  | Keystone   | Crear proyecto `poc-project` y usuario `poc-user` con rol `member` | `POST /v3/projects`, `POST /v3/users`                    |
| 6/8  | Keycloak   | Habilitar permisos fine-grained en IdP y cliente                   | `PUT .../management/permissions`                         |
| 7/8  | Keycloak   | Crear politica de role y vincular a permisos token-exchange        | `POST .../authz/resource-server/policy/role`             |
| 8/8  | Keycloak   | Vincular usuario `poc-user` al IdP keystone-idp (federated link)   | `POST .../federated-identity/keystone-idp`               |

### Comandos utiles

```bash
# Ver logs de Keycloak
docker logs poc-identity-keycloak-1 --tail 20

# Ver logs del Adapter
docker logs poc-identity-keystone-adapter-1 --tail 20

# Ver logs de Keystone
docker logs poc-identity-keystone-1 --tail 20

# Reiniciar un servicio
docker-compose restart keycloak

# Parar todo
docker-compose down

# Parar y borrar datos (empezar de cero)
docker-compose down -v
```

## Resultado del Demo

```
======================================================================
  FLUJO DE IDENTIDAD FEDERADA: KEYSTONE -> KEYCLOAK -> JWT
======================================================================

[STEP 1] Autenticando en OpenStack Keystone...
  OK - Token Keystone: gAAAAABpmdcLAKi3xmW3CVQkgG9cDj8KY-dl...

[STEP 2] Enviando token a Keycloak (Token Exchange RFC 8693)...
  -> Keycloak llama al Adapter para validar contra Keystone...
  OK - Keycloak ha emitido un JWT firmado

[STEP 3] Analizando el JWT recibido:
----------------------------------------------------------------------
  Usuario:  poc-user
  Emisor:   http://localhost:8080/realms/cloud-orch
  Scopes:   profile email
----------------------------------------------------------------------

======================================================================
  PRUEBA DE CONCEPTO COMPLETADA CON EXITO
======================================================================
```

## Caso de Uso: Un JWT para Todos los Servicios

El principal valor de esta arquitectura es que el **orquestador cloud solo necesita gestionar
2 tokens**, independientemente del numero de servicios integrados:

```
  Orquestador Cloud
       |
       | Login en Keystone (una sola vez)
       |
       +--> Token Keystone (Fernet) --> Operaciones OpenStack
       |                                (VMs, redes, storage...)
       |
       +--> Token Exchange --> JWT Keycloak --> TODOS los servicios
                                                |
                                    +-----------+-----------+
                                    |           |           |
                                 Commvault    Veeam    Otros servicios
```

### Como funciona

| Token               | Uso                       | Gestion                               |
| ------------------- | ------------------------- | ------------------------------------- |
| **Keystone Fernet** | Operaciones OpenStack     | Lo emite Keystone al hacer login      |
| **Keycloak JWT**    | Todos los demas servicios | Se obtiene UNA vez via token exchange |

### Que valida cada servicio

El JWT de Keycloak es **autocontenido** — cada servicio lo valida por si solo, sin
necesidad de contactar a Keycloak en tiempo real:

1. Descargar la clave publica de Keycloak (endpoint JWKS, se cachea)
2. Verificar la firma RSA-256 del JWT
3. Comprobar que no ha expirado (`exp`)
4. Verificar que el emisor (`iss`) es el Keycloak de confianza

Esto significa que:

- **No hay cuello de botella** en Keycloak durante la operacion normal
- **No hay latencia adicional** — la validacion es local y criptografica
- **Un solo token** sirve para Commvault, Veeam, y cualquier otro servicio que
  confie en Keycloak como Identity Provider
- Si se necesita **revocar acceso**, se revoca la sesion en Keycloak y el token
  expira naturalmente (o se configura token introspection para revocacion inmediata)

## Configuracion Avanzada para Produccion

### 1. Mapeo de Roles (Commvault/Veeam)

Para que servicios como Commvault o Veeam asignen permisos automaticamente, Keycloak puede inyectar "Roles" en el JWT basados en Keystone:

- **Mappers**: Se configura un "Protocol Mapper" en el Identity Provider de Keycloak.
- **Funcion**: Transforma los _Proyectos_ o _Roles_ de OpenStack en _Groups_ o _Claims_ del JWT.
- **Resultado**: El JWT final contendria algo como `"roles": ["BackupAdmin", "RestoreUser"]`, que la aplicacion final entiende de forma nativa.

### 2. Ciclo de Vida y Revocacion

- **Validacion en Tiempo Real**: Gracias al **Keystone Adapter**, cada vez que Keycloak necesita validar el token externo (durante el exchange o introspeccion), llama a Keystone. Si el token de Keystone ha sido borrado o revocado, Keycloak denegara el acceso inmediatamente.
- **Seguridad**: Esto elimina el riesgo de tener un JWT valido si el usuario ya no tiene acceso en OpenStack.

### 3. Provisionamiento de Usuarios (JIT)

- **Modo IMPORT**: En esta POC, Keycloak importa el perfil del usuario la primera vez que hace login (Just-in-Time). Esto permite que las aplicaciones busquen al usuario en el directorio de Keycloak aun si nunca han entrado por el flujo OIDC directamente.

## Archivos del Proyecto

```
poc-identity/
  docker-compose.yml        # Orquestacion: Keystone, Keycloak, Adapter
  setup.py                  # CONFIGURACION AUTOMATICA (Ejecutar primero)
  demo.py                   # Prueba de concepto del flujo completo
  README_POC.md             # Guia tecnica (este archivo)
  README_POC.html           # Reporte visual premium
  .gitignore                # Exclusion de datos temporales
  app/
    keystone_adapter.py     # Microservicio traductor de protocolos
  keystone_config/
    keystone.conf           # Configuracion base de OpenStack
    config.json             # Metadatos para el bootstrap de Kolla
    start_keystone.sh       # Script de arranque y Fernet setup
```
