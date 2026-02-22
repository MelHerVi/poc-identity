# 🔐 POC: Identity Bridge — Keystone ↔ Keycloak

Prueba de concepto de **federación de identidad** entre OpenStack Keystone y Keycloak.  
Un token Fernet de Keystone se intercambia por un JWT firmado por Keycloak usando **RFC 8693 (Token Exchange)**.

```
Keystone (Fernet) ──► Adapter ──► Keycloak ──► JWT (RS256)
```

## Requisitos

- **Docker** y **Docker Compose**
- **Python 3.x** con `requests`

```bash
pip install requests
```

## Instalación

```bash
# 1. Clonar el repositorio
git clone <url-del-repo> && cd poc-identity

# 2. Levantar los servicios
docker-compose up -d

# 3. Ejecutar el setup automático (espera a los servicios y configura todo)
python setup.py

# 4. Ejecutar la demo
python demo.py
```

## Resultado esperado

```
======================================================================
  FLUJO DE IDENTIDAD FEDERADA: KEYSTONE -> KEYCLOAK -> JWT
======================================================================

[STEP 1] Autenticando en OpenStack Keystone...
  OK - Token Keystone: gAAAAABpmdcLAKi3xmW3...

[STEP 2] Enviando token a Keycloak (Token Exchange RFC 8693)...
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

## Limpieza

```bash
python cleanup.py
```

## Estructura del proyecto

```
poc-identity/
├── docker-compose.yml        # Orquestación de contenedores
├── setup.py                  # Configuración automática (ejecutar primero)
├── demo.py                   # Prueba del flujo completo
├── cleanup.py                # Limpieza del entorno
├── README.md                 # Este archivo
├── README_POC.md             # Documentación técnica detallada
├── README_POC.html           # Reporte visual
├── app/
│   └── keystone_adapter.py   # Bridge: traduce OpenStack API → OIDC
└── keystone_config/
    ├── keystone.conf          # Configuración de Keystone
    ├── config.json            # Metadatos para Kolla
    └── start_keystone.sh      # Script de arranque
```

## Documentación

| Documento                              | Contenido                                                                            |
| -------------------------------------- | ------------------------------------------------------------------------------------ |
| **[README_POC.md](README_POC.md)**     | Arquitectura, estándares (RFC 7662, 8693), desafíos técnicos, configuración avanzada |
| **[README_POC.html](README_POC.html)** | Reporte visual premium con diagramas y flujos (abrir en navegador)                   |

## Stack

| Servicio | Imagen                                                   | Puerto |
| -------- | -------------------------------------------------------- | ------ |
| Keystone | `quay.io/openstack.kolla/ubuntu-binary-keystone:wallaby` | 5000   |
| Keycloak | `quay.io/keycloak/keycloak:latest`                       | 8080   |
| Adapter  | `python:3.9-slim` + Flask                                | 8000   |
| Database | `mariadb:10.5`                                           | —      |
