"""
LIMPIEZA COMPLETA - Elimina todos los recursos del POC
=======================================================
Ejecutar: python cleanup.py

Este script elimina:
  - Contenedores Docker del POC
  - Volumenes de datos
  - Red Docker
  - Datos locales de Keycloak
"""

import subprocess
import shutil
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYCLOAK_DATA = os.path.join(BASE_DIR, "keycloak_data")


def run(cmd, check=False):
    """Ejecuta un comando y devuelve True si fue exitoso."""
    try:
        subprocess.run(
            cmd,
            shell=True,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            check=check,
        )
        return True
    except subprocess.CalledProcessError:
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("  LIMPIEZA COMPLETA DEL POC DE IDENTIDAD FEDERADA")
    print("=" * 60)

    # 1. Parar y eliminar contenedores + volumenes + red
    print("\n[1/3] Eliminando contenedores, volumenes y red...")
    if run("docker-compose down -v --remove-orphans"):
        print("  OK - Contenedores y volumenes eliminados")
    else:
        print("  WARN - docker-compose no disponible o ya limpio")

    # 2. Eliminar datos locales de Keycloak
    print("\n[2/3] Eliminando datos locales de Keycloak...")
    if os.path.exists(KEYCLOAK_DATA):
        shutil.rmtree(KEYCLOAK_DATA, ignore_errors=True)
        print(f"  OK - {KEYCLOAK_DATA} eliminado")
    else:
        print("  Ya limpio (no existe keycloak_data/)")

    # 3. Eliminar imagenes Docker (opcional)
    print("\n[3/3] Imagenes Docker descargadas:")
    images = [
        "quay.io/openstack.kolla/ubuntu-binary-keystone:wallaby",
        "quay.io/keycloak/keycloak:latest",
        "mariadb:10.5",
        "python:3.9-slim",
    ]
    for img in images:
        print(f"  - {img}")
    print("  (No se eliminan automaticamente. Para borrarlas:")
    print("   docker rmi " + " ".join(images) + ")")

    print("\n" + "=" * 60)
    print("  LIMPIEZA COMPLETADA")
    print("  Para volver a montar el entorno:")
    print("    docker-compose up -d")
    print("    python setup.py")
    print("    python demo.py")
    print("=" * 60)
