#!/usr/bin/env python3
# ============================================================================
# K8S TOKEN EXTRACTOR
# ============================================================================
# Extrae token, CA y namespace de un pod y genera un kubeconfig listo para usar
# También puede construir un kubeconfig a partir de archivos de token, CA y namespace
#
# Uso (modo pod):
#   python3 k8s_token_extractor.py -k <kubeconfig> -n <namespace> -p <pod> [opciones]
#
# Uso (modo manual):
#   python3 k8s_token_extractor.py -t <token-file> -a <api-server> [-c <ca.crt>] [-n <namespace>] [-s <sa-name>]
#
# Ejemplo:
#   python3 k8s_token_extractor.py -k initial-kubeconfig.yaml -n mirror-world -p machine-697bff775f-49qsh
#   python3 k8s_token_extractor.py -t token.txt -c ca.crt -n mirror-world -a https://10.10.10.1:6443 -s my-sa
# ============================================================================

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ============================================================================
# Colores para output
# ============================================================================
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"

# ============================================================================
# Variables globales
# ============================================================================
OUTPUT_DIR = "./generated_kubeconfigs"
API_SERVER = ""
VERBOSE = False
MANUAL_MODE = False
TOKEN_FILE = ""
CA_FILE = ""
CONTEXT_NAME = ""
CLUSTER_NAME = ""
KUBECONFIG = ""
NAMESPACE = ""
POD = ""
SA_NAME = ""

# JWT decoded state
JWT_SA = ""
JWT_NS = ""
JWT_DECODED = ""

# Extracted credentials
TOKEN = ""
CA = ""
POD_NAMESPACE = ""


# ============================================================================
# Funciones de logging
# ============================================================================
def log_info(msg):
    print(f"{GREEN}[INFO]{NC} {msg}")


def log_error(msg):
    print(f"{RED}[ERROR]{NC} {msg}")


def log_warn(msg):
    print(f"{YELLOW}[WARN]{NC} {msg}")


def log_debug(msg):
    if VERBOSE:
        print(f"{BLUE}[DEBUG]{NC} {msg}")


# ============================================================================
# Ejecutar comando externo
# ============================================================================
def run_cmd(cmd, capture=True, check=False):
    """Ejecuta un comando y retorna (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            check=check,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout or "", e.stderr or ""
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"


# ============================================================================
# Función de ayuda
# ============================================================================
def show_help():
    script = os.path.basename(sys.argv[0])
    print(f"""{BLUE}K8S Token Extractor - Extrae token, CA y namespace de un pod y genera un kubeconfig{NC}

{YELLOW}MODO 1 - EXTRACCIÓN DESDE POD:{NC}
  {script} -k <kubeconfig> -n <namespace> -p <pod> [opciones]

{YELLOW}MODO 2 - CONSTRUCCIÓN MANUAL:{NC}
  {script} -t <token-file> -a <api-server> [-c <ca.crt>] [-n <namespace>] [-s <sa-name>] [opciones]

{YELLOW}PARÁMETROS MODO POD:{NC}
  -k <kubeconfig> Ruta al kubeconfig actual (ej: ./kubeconfig.yaml)
  -n <namespace>  Namespace donde está el pod (ej: production)
  -p <pod>        Nombre exacto del pod (ej: webapp-deploy-7f8b9c6d4-x2k9m)

{YELLOW}PARÁMETROS MODO MANUAL:{NC}
  -t <token-file> Ruta al archivo con el token del ServiceAccount
  -c <ca.crt>    Ruta al archivo CA certificate (ca.crt). Si no se especifica, se genera
                 kubeconfig en modo inseguro (insecure-skip-tls-verify: true)
  -n <namespace>  Namespace (si no se especifica, se extrae del token JWT)
  -a <url>       URL del API server (obligatorio en modo manual)
  -s <sa-name>   Nombre del ServiceAccount (si no se especifica, se extrae del token JWT)

{YELLOW}OPCIONES ADICIONALES:{NC}
  -a <url>       URL del API server (en modo pod se obtiene del kubeconfig si no se especifica)
  -x <context>   Nombre del contexto en el kubeconfig (por defecto: context)
  -l <cluster>   Nombre del cluster en el kubeconfig (por defecto: cluster)
  -o <output-dir> Directorio de salida (por defecto: ./SA_<sa-name>)
  -v             Modo verbose (muestra TOKEN INTELLIGENCE REPORT con detalles del JWT)
  -h             Muestra esta ayuda

{YELLOW}EJEMPLOS:{NC}
  # Modo pod: extraer desde un pod en ejecución
  {script} -k kubeconfig.yaml -n production -p webapp-deploy-7f8b9c6d4-x2k9m
  {script} -k admin.conf -n monitoring -p prometheus-server-5c8f7d-r4j2p -a https://kubernetes.default.svc -v

  # Modo manual: construir desde archivos existentes
  {script} -t token.txt -c ca.crt -n production -a https://10.10.10.1:6443
  {script} -t /tmp/token -c /tmp/ca.crt -n kube-system -a https://k8s.example.com:6443 -s deploy-sa -o ./output""")


# ============================================================================
# Decodificar token JWT y extraer campos
# ============================================================================
def decode_jwt_payload(token_source, is_file=True):
    """Decodifica el payload de un JWT y extrae SA y namespace."""
    global JWT_SA, JWT_NS, JWT_DECODED

    if is_file:
        try:
            with open(token_source, "r") as f:
                token = f.read().strip().replace("\r", "").replace("\n", "")
        except (IOError, OSError):
            return False
    else:
        token = token_source.strip().replace("\r", "").replace("\n", "")

    parts = token.split(".")
    if len(parts) < 2:
        return False

    payload = parts[1]
    if not payload:
        return False

    # Padding base64url -> base64
    pad = 4 - len(payload) % 4
    if pad < 4:
        payload += "=" * pad
    payload = payload.replace("_", "/").replace("-", "+")

    try:
        decoded_bytes = base64.b64decode(payload)
        JWT_DECODED = decoded_bytes.decode("utf-8", errors="replace")
    except Exception:
        return False

    if not JWT_DECODED:
        return False

    # Extraer sub
    try:
        jwt_data = json.loads(JWT_DECODED)
        sub = jwt_data.get("sub", "")
        if sub:
            parts_sub = sub.split(":")
            if len(parts_sub) >= 2:
                JWT_NS = parts_sub[-2]
                JWT_SA = parts_sub[-1]
    except json.JSONDecodeError:
        # Fallback con regex como el bash original
        match = re.search(r'"sub":"([^"]*)"', JWT_DECODED)
        if match:
            sub = match.group(1)
            parts_sub = sub.split(":")
            if len(parts_sub) >= 2:
                JWT_NS = parts_sub[-2]
                JWT_SA = parts_sub[-1]

    return True


def jwt_field(field):
    """Extraer un campo string del JSON decodificado."""
    if not JWT_DECODED:
        return ""
    try:
        data = json.loads(JWT_DECODED)
        val = data.get(field, "")
        if isinstance(val, str):
            return val
        return ""
    except json.JSONDecodeError:
        match = re.search(rf'"{re.escape(field)}":"([^"]*)"', JWT_DECODED)
        return match.group(1) if match else ""


def jwt_field_num(field):
    """Extraer un campo numérico del JSON decodificado."""
    if not JWT_DECODED:
        return None
    try:
        data = json.loads(JWT_DECODED)
        val = data.get(field)
        if isinstance(val, (int, float)):
            return int(val)
        return None
    except json.JSONDecodeError:
        match = re.search(rf'"{re.escape(field)}":(\d+)', JWT_DECODED)
        return int(match.group(1)) if match else None


def jwt_nested_field(path_keys):
    """Extraer un campo anidado del JSON decodificado. path_keys es lista de keys."""
    if not JWT_DECODED:
        return ""
    try:
        data = json.loads(JWT_DECODED)
        current = data
        for key in path_keys:
            if isinstance(current, dict):
                current = current.get(key, "")
            else:
                return ""
        return current if isinstance(current, str) else ""
    except (json.JSONDecodeError, TypeError):
        return ""


# ============================================================================
# Reporte de inteligencia del token JWT
# ============================================================================
def show_token_report(token_source, is_file=True):
    """Muestra el TOKEN INTELLIGENCE REPORT."""
    global JWT_DECODED

    # Decodificar si no se hizo antes
    if not JWT_DECODED:
        decode_jwt_payload(token_source, is_file)

    if not JWT_DECODED:
        log_warn("No se pudo decodificar el token JWT para generar el reporte.")
        return False

    # --- Extraer campos básicos ---
    iss = jwt_field("iss")
    sub = jwt_field("sub")
    exp = jwt_field_num("exp")
    iat = jwt_field_num("iat")
    nbf = jwt_field_num("nbf")
    jti = jwt_field("jti")

    # aud puede ser string o array
    aud = ""
    try:
        data = json.loads(JWT_DECODED)
        aud_val = data.get("aud", "")
        if isinstance(aud_val, list):
            aud = ", ".join(aud_val)
        elif isinstance(aud_val, str):
            aud = aud_val
    except json.JSONDecodeError:
        aud = jwt_field("aud")

    # --- Campos K8s: soportar formato nested y flat ---
    k8s_ns = ""
    k8s_sa = ""
    k8s_sa_uid = ""
    k8s_pod = ""
    k8s_pod_uid = ""
    k8s_node = ""
    k8s_node_uid = ""

    try:
        data = json.loads(JWT_DECODED)
        k8s_io = data.get("kubernetes.io", {})
        if isinstance(k8s_io, dict):
            # Formato nested (projected tokens)
            k8s_ns = k8s_io.get("namespace", "")
            pod_info = k8s_io.get("pod", {})
            if isinstance(pod_info, dict):
                k8s_pod = pod_info.get("name", "")
                k8s_pod_uid = pod_info.get("uid", "")
            node_info = k8s_io.get("node", {})
            if isinstance(node_info, dict):
                k8s_node = node_info.get("name", "")
                k8s_node_uid = node_info.get("uid", "")
            sa_info = k8s_io.get("serviceaccount", {})
            if isinstance(sa_info, dict):
                k8s_sa = sa_info.get("name", "")
                k8s_sa_uid = sa_info.get("uid", "")

        # Fallback: formato flat (legacy tokens)
        if not k8s_ns:
            k8s_ns = data.get("kubernetes.io/serviceaccount/namespace", "")
        if not k8s_sa:
            k8s_sa = data.get("kubernetes.io/serviceaccount/service-account.name", "")
        if not k8s_sa_uid:
            k8s_sa_uid = data.get("kubernetes.io/serviceaccount/service-account.uid", "")
        if not k8s_pod:
            k8s_pod = data.get("kubernetes.io/pod/name", "")
        if not k8s_node:
            k8s_node = data.get("kubernetes.io/node/name", "")
    except json.JSONDecodeError:
        # Fallback con regex como el bash original
        for pattern, target in [
            (r'"kubernetes\.io/serviceaccount/namespace":"([^"]*)"', "k8s_ns"),
            (r'"kubernetes\.io/serviceaccount/service-account\.name":"([^"]*)"', "k8s_sa"),
            (r'"kubernetes\.io/serviceaccount/service-account\.uid":"([^"]*)"', "k8s_sa_uid"),
            (r'"kubernetes\.io/pod/name":"([^"]*)"', "k8s_pod"),
            (r'"kubernetes\.io/node/name":"([^"]*)"', "k8s_node"),
        ]:
            m = re.search(pattern, JWT_DECODED)
            if m:
                locals()[target] = m.group(1)

    # Usar sub como fallback para namespace/sa
    sa_ns = k8s_ns or JWT_NS
    sa_name = k8s_sa or JWT_SA

    # --- Detectar proveedor cloud y extraer info del issuer URL ---
    cloud_provider = ""
    cloud_service = ""
    cloud_project = ""
    cloud_region = ""
    cluster_name = ""

    if iss:
        iss_lower = iss.lower()
        if "container.googleapis.com" in iss_lower:
            cloud_provider = "Google Cloud Platform (GCP)"
            cloud_service = "Google Kubernetes Engine (GKE)"
            m = re.search(r"projects/([^/]+)", iss)
            if m:
                cloud_project = m.group(1)
            m = re.search(r"locations/([^/]+)", iss)
            if m:
                cloud_region = m.group(1)
            m = re.search(r"clusters/([^/]+)", iss)
            if m:
                cluster_name = m.group(1)
        elif "eks.amazonaws.com" in iss_lower or "oidc.eks" in iss_lower:
            cloud_provider = "Amazon Web Services (AWS)"
            cloud_service = "Elastic Kubernetes Service (EKS)"
            m = re.search(r"eks\.([a-z]+-[a-z]+-[0-9]+)", iss)
            if m:
                cloud_region = m.group(1)
            m = re.search(r"id/([^/]+)", iss)
            if m:
                cloud_project = m.group(1)
        elif any(x in iss_lower for x in ["azmk8s.io", "azure", "login.microsoftonline.com"]):
            cloud_provider = "Microsoft Azure"
            cloud_service = "Azure Kubernetes Service (AKS)"
            m = re.search(r"https://([a-z]+)(?=\.oic\.prod-aks)", iss)
            if m:
                cloud_region = m.group(1)
        elif "kubernetes.default" in iss_lower or "kubernetes.svc" in iss_lower:
            cloud_provider = "Self-Hosted / On-Premise"
            cloud_service = "Kubernetes"

    # Fallback: extraer region del nombre del nodo
    if not cloud_region and k8s_node:
        m = re.search(r"[a-z]+-[a-z]+[0-9]+-[a-z]", k8s_node)
        if m:
            cloud_region = m.group(0)

    # --- Timestamps ---
    iat_str = "N/A"
    exp_str = "N/A"
    status = ""
    status_color = ""
    time_detail = ""
    now = int(time.time())

    if iat and iat > 0:
        try:
            iat_str = datetime.fromtimestamp(iat, tz=timezone.utc).strftime("%d-%b-%Y %H:%M:%S UTC")
        except (OSError, ValueError):
            iat_str = str(iat)

    if exp and exp > 0:
        try:
            exp_str = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%d-%b-%Y %H:%M:%S UTC")
        except (OSError, ValueError):
            exp_str = str(exp)

        if now > exp:
            expired_ago = now - exp
            days = expired_ago // 86400
            hours = (expired_ago % 86400) // 3600
            status = "EXPIRADO"
            status_color = RED
            time_detail = f"(hace {days}d {hours}h)"
        else:
            remaining = exp - now
            days = remaining // 86400
            hours = (remaining % 86400) // 3600
            if days < 7:
                status = "ACTIVO - EXPIRA PRONTO"
                status_color = YELLOW
            else:
                status = "ACTIVO"
                status_color = GREEN
            time_detail = f"(quedan {days}d {hours}h)"
    else:
        status = "SIN EXPIRACIÓN"
        status_color = YELLOW
        time_detail = "(token sin fecha de expiración)"

    # --- Calcular vida útil del token ---
    token_lifetime = "N/A"
    if iat and exp and iat > 0 and exp > 0:
        lifetime = exp - iat
        lt_days = lifetime // 86400
        lt_hours = (lifetime % 86400) // 3600
        token_lifetime = f"{lt_days}d {lt_hours}h"

    # --- Imprimir reporte ---
    print()
    print(f"{BLUE}╔══════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BLUE}║          TOKEN INTELLIGENCE REPORT                          ║{NC}")
    print(f"{BLUE}╚══════════════════════════════════════════════════════════════╝{NC}")
    print()
    print(f"{YELLOW}--- [ENTORNO DEL CLÚSTER] ---{NC}")
    if cloud_provider:
        print(f"  PROVEEDOR CLOUD:     {GREEN}{cloud_provider}{NC}")
    if cloud_service:
        print(f"  SERVICIO:            {cloud_service}")
    if cloud_project:
        print(f"  ID PROYECTO:         {cloud_project}")
    if cloud_region:
        print(f"  ZONA GEOGRÁFICA:     {cloud_region}")
    if cluster_name:
        print(f"  CLUSTER NAME:        {cluster_name}")
    if iss:
        print(f"  ISSUER URL:          {iss}")
    if API_SERVER:
        print(f"  API SERVER URL:      {API_SERVER}")
    print()
    print(f"{YELLOW}--- [IDENTIDAD KUBERNETES] ---{NC}")
    if sa_ns:
        print(f"  NAMESPACE:           {GREEN}{sa_ns}{NC}")
    if sa_name:
        print(f"  SERVICE ACCOUNT:     {GREEN}{sa_name}{NC}")
    if k8s_sa_uid:
        print(f"  SA UID:              {k8s_sa_uid}")
    if k8s_pod:
        print(f"  POD ORIGEN:          {k8s_pod}")
    if k8s_pod_uid:
        print(f"  POD UID:             {k8s_pod_uid}")
    if k8s_node:
        print(f"  NODO ASIGNADO:       {k8s_node}")
    if k8s_node_uid:
        print(f"  NODO UID:            {k8s_node_uid}")
    if sub:
        print(f"  SUBJECT COMPLETO:    {sub}")
    print()
    print(f"{YELLOW}--- [ESTADO DE SEGURIDAD] ---{NC}")
    if aud:
        print(f"  AUDIENCIA (aud):     {aud}")
    print(f"  FECHA CREACIÓN:      {iat_str}")
    print(f"  FECHA EXPIRACIÓN:    {exp_str}")
    print(f"  VIDA ÚTIL TOKEN:     {token_lifetime}")
    print(f"  STATUS:              {status_color}{status} {time_detail}{NC}")
    print(f"{BLUE}══════════════════════════════════════════════════════════════{NC}")

    return True


# ============================================================================
# Verificación de dependencias
# ============================================================================
def check_dependencies():
    dependencies = ["kubectl", "base64"]
    missing = False

    for cmd in dependencies:
        if shutil.which(cmd) is None:
            log_error(f"Falta dependencia requerida: {cmd}")
            missing = True

    if missing:
        log_error("Por favor, instala las dependencias faltantes para continuar.")
        sys.exit(1)


# ============================================================================
# Verificación de conectividad y permisos
# ============================================================================
def check_access():
    log_info("Verificando acceso al clúster...")

    # 1. Verificar si podemos hablar con el API server
    rc1, _, _ = run_cmd(["kubectl", f"--kubeconfig={KUBECONFIG}", "get", "ns"])
    rc2, _, _ = run_cmd(["kubectl", f"--kubeconfig={KUBECONFIG}", "auth", "can-i", "get", "pods"])

    if rc1 != 0 and rc2 != 0:
        rc3, _, _ = run_cmd(["kubectl", f"--kubeconfig={KUBECONFIG}", "cluster-info"])
        if rc3 != 0:
            log_error("No se puede conectar al API server. Verifica tu kubeconfig y conectividad.")
            return False

    # 2. Verificar si el pod existe
    rc, _, _ = run_cmd(["kubectl", f"--kubeconfig={KUBECONFIG}", "get", "pod", "-n", NAMESPACE, POD])
    if rc != 0:
        rc_ns, _, _ = run_cmd(["kubectl", f"--kubeconfig={KUBECONFIG}", "get", "pod", "-n", NAMESPACE])
        if rc_ns != 0:
            log_warn(f"No se pudo verificar el namespace '{NAMESPACE}' o no tienes permisos para listar pods en él.")
        log_error(f"No se encuentra el pod '{POD}' en el namespace '{NAMESPACE}'.")
        log_error("Posibles causas: Nombre incorrecto, namespace incorrecto, o falta de permisos.")
        return False
    log_info("Conectividad y Pod OK")

    # Verificar permisos de exec
    log_info("Verificando permisos de extracción...")
    rc, _, _ = run_cmd([
        "kubectl", f"--kubeconfig={KUBECONFIG}", "auth", "can-i",
        "create", "pods", "--subresource=exec", "-n", NAMESPACE,
    ])
    if rc != 0:
        log_error(f"No tienes permisos para ejecutar comandos (exec) en el namespace {NAMESPACE}")
        log_error("   Requerido: create pods/exec")
        log_error("   Sin este permiso, no es posible leer los archivos del pod.")
        return False
    log_info("Permisos de extracción (exec) OK")

    # Verificar exec real
    log_debug(f"Verificando exec en {NAMESPACE}/{POD}")
    rc, _, _ = run_cmd([
        "kubectl", f"--kubeconfig={KUBECONFIG}", "exec", "-n", NAMESPACE, POD, "--", "true",
    ])
    if rc != 0:
        log_error(f"Tienes el permiso teórico, pero falló la conexión al pod {NAMESPACE}/{POD}")
        log_error("Posibles causas: Pod terminando, problemas de red, o contenedor sin shell/binarios básicos.")
        return False
    log_info("Acceso real al pod OK")

    return True


# ============================================================================
# Extraer token, CA y namespace del pod
# ============================================================================
def extract_from_pod():
    global TOKEN, CA, POD_NAMESPACE

    log_info("Extrayendo token del pod...")
    rc, stdout, _ = run_cmd([
        "kubectl", f"--kubeconfig={KUBECONFIG}", "exec", "-n", NAMESPACE, POD,
        "--", "cat", "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ])
    TOKEN = stdout.strip().replace("\r", "").replace("\n", "")
    if not TOKEN:
        log_error("No se pudo extraer el token")
        sys.exit(1)
    log_debug(f"Token extraído ({len(TOKEN)} caracteres)")

    log_info("Extrayendo CA certificate...")
    rc, stdout, _ = run_cmd([
        "kubectl", f"--kubeconfig={KUBECONFIG}", "exec", "-n", NAMESPACE, POD,
        "--", "cat", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    ])
    CA = "\n".join(line.strip() for line in stdout.splitlines() if line.strip())
    if not CA:
        log_error("No se pudo extraer el CA certificate")
        sys.exit(1)
    log_debug(f"CA extraído ({len(CA)} caracteres)")

    log_info("Extrayendo namespace del pod...")
    rc, stdout, _ = run_cmd([
        "kubectl", f"--kubeconfig={KUBECONFIG}", "exec", "-n", NAMESPACE, POD,
        "--", "cat", "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    ])
    POD_NAMESPACE = stdout.strip().replace("\r", "").replace("\n", "")
    if not POD_NAMESPACE:
        log_warn(f"No se pudo extraer el namespace, usando '{NAMESPACE}' por defecto")
        POD_NAMESPACE = NAMESPACE
    log_debug(f"Namespace extraído: {POD_NAMESPACE}")

    # Guardar archivos individuales con permisos seguros
    _write_file(os.path.join(OUTPUT_DIR, "token.txt"), TOKEN, mode=0o600)
    _write_file(os.path.join(OUTPUT_DIR, "ca.crt"), CA, mode=0o600)
    _write_file(os.path.join(OUTPUT_DIR, "namespace.txt"), POD_NAMESPACE, mode=0o600)

    log_info(f"Archivos guardados en {OUTPUT_DIR}/ (permisos 600)")


# ============================================================================
# Determinar API server
# ============================================================================
def get_api_server():
    if API_SERVER:
        log_debug(f"Usando API server especificado: {API_SERVER}")
        return API_SERVER

    # Intentar obtener del kubeconfig
    rc, stdout, _ = run_cmd([
        "kubectl", f"--kubeconfig={KUBECONFIG}", "config", "view",
        "--minify", "-o", "jsonpath={.clusters[0].cluster.server}",
    ])
    api = stdout.strip()
    if api:
        log_debug(f"API server obtenido del kubeconfig: {api}")
        return api

    # Fallback
    log_warn("No se pudo determinar API server, usando https://kubernetes.default.svc")
    return "https://kubernetes.default.svc"


# ============================================================================
# Generar kubeconfig
# ============================================================================
def generate_kubeconfig(api_server):
    ctx_name = CONTEXT_NAME or "context"
    cls_name = CLUSTER_NAME or "cluster"

    output_file = os.path.join(OUTPUT_DIR, f"kubeconfig_{NAMESPACE}_{SA_NAME}.yaml")

    log_debug(f"ServiceAccount identificado: {SA_NAME}")

    if CA:
        # Modo seguro: con certificate-authority-data
        ca_b64 = base64.b64encode(CA.encode("utf-8")).decode("utf-8")
        content = f"""apiVersion: v1
kind: Config
clusters:
- name: {cls_name}
  cluster:
    server: {api_server}
    certificate-authority-data: {ca_b64}
contexts:
- name: {ctx_name}
  context:
    cluster: {cls_name}
    user: {SA_NAME}
    namespace: {POD_NAMESPACE}
current-context: {ctx_name}
users:
- name: {SA_NAME}
  user:
    token: {TOKEN}
"""
    else:
        # Modo inseguro: sin CA, skip TLS verify
        content = f"""apiVersion: v1
kind: Config
clusters:
- name: {cls_name}
  cluster:
    server: {api_server}
    insecure-skip-tls-verify: true
contexts:
- name: {ctx_name}
  context:
    cluster: {cls_name}
    user: {SA_NAME}
    namespace: {POD_NAMESPACE}
current-context: {ctx_name}
users:
- name: {SA_NAME}
  user:
    token: {TOKEN}
"""

    _write_file(output_file, content, mode=0o600)
    log_info(f"Kubeconfig generado: {output_file} (permisos 600)")


# ============================================================================
# Cargar credenciales desde archivos (modo manual)
# ============================================================================
def load_from_files():
    global TOKEN, CA, POD_NAMESPACE

    log_info(f"Cargando token desde archivo: {TOKEN_FILE}")
    try:
        with open(TOKEN_FILE, "r") as f:
            TOKEN = f.read().strip().replace("\r", "").replace("\n", "")
    except (IOError, OSError) as e:
        log_error(f"Error leyendo token: {e}")
        sys.exit(1)

    if not TOKEN:
        log_error(f"El archivo de token está vacío: {TOKEN_FILE}")
        sys.exit(1)
    log_debug(f"Token cargado ({len(TOKEN)} caracteres)")

    if CA_FILE:
        log_info(f"Cargando CA certificate desde archivo: {CA_FILE}")
        try:
            with open(CA_FILE, "r") as f:
                CA = "\n".join(line.strip() for line in f if line.strip())
        except (IOError, OSError) as e:
            log_error(f"Error leyendo CA: {e}")
            sys.exit(1)

        if not CA:
            log_error(f"El archivo CA está vacío: {CA_FILE}")
            sys.exit(1)
        log_debug(f"CA cargado ({len(CA)} caracteres)")
    else:
        CA = ""
        log_warn("Sin CA certificate (-c). Se generará kubeconfig en modo inseguro (insecure-skip-tls-verify)")
        print()
        try:
            confirm = input("  ¿Deseas continuar sin CA certificate? (y/N): ").strip()
        except (EOFError, KeyboardInterrupt):
            confirm = ""
        if confirm.lower() not in ("y", "s"):
            log_info("Operación cancelada por el usuario.")
            sys.exit(0)

    POD_NAMESPACE = NAMESPACE
    log_debug(f"Namespace: {POD_NAMESPACE}")

    # Guardar copias en el directorio de salida
    _write_file(os.path.join(OUTPUT_DIR, "token.txt"), TOKEN, mode=0o600)
    if CA:
        _write_file(os.path.join(OUTPUT_DIR, "ca.crt"), CA, mode=0o600)
    _write_file(os.path.join(OUTPUT_DIR, "namespace.txt"), POD_NAMESPACE, mode=0o600)

    log_info(f"Archivos copiados en {OUTPUT_DIR}/ (permisos 600)")


# ============================================================================
# Helpers
# ============================================================================
def _write_file(path, content, mode=None):
    """Escribe contenido a un archivo y opcionalmente establece permisos."""
    with open(path, "w") as f:
        f.write(content)
    if mode is not None:
        os.chmod(path, mode)


# ============================================================================
# Parseo de argumentos
# ============================================================================
def parse_args():
    global KUBECONFIG, NAMESPACE, POD, API_SERVER, OUTPUT_DIR
    global TOKEN_FILE, CA_FILE, SA_NAME, CONTEXT_NAME, CLUSTER_NAME
    global VERBOSE, MANUAL_MODE

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-k", dest="kubeconfig", default="")
    parser.add_argument("-n", dest="namespace", default="")
    parser.add_argument("-p", dest="pod", default="")
    parser.add_argument("-a", dest="api_server", default="")
    parser.add_argument("-o", dest="output_dir", default="./generated_kubeconfigs")
    parser.add_argument("-t", dest="token_file", default="")
    parser.add_argument("-c", dest="ca_file", default="")
    parser.add_argument("-s", dest="sa_name", default="")
    parser.add_argument("-x", dest="context_name", default="")
    parser.add_argument("-l", dest="cluster_name", default="")
    parser.add_argument("-v", dest="verbose", action="store_true")
    parser.add_argument("-h", dest="show_help", action="store_true")

    args = parser.parse_args()

    if args.show_help:
        show_help()
        sys.exit(0)

    KUBECONFIG = args.kubeconfig
    NAMESPACE = args.namespace
    POD = args.pod
    API_SERVER = args.api_server
    OUTPUT_DIR = args.output_dir
    TOKEN_FILE = args.token_file
    CA_FILE = args.ca_file
    SA_NAME = args.sa_name
    CONTEXT_NAME = args.context_name
    CLUSTER_NAME = args.cluster_name
    VERBOSE = args.verbose

    # Detectar modo manual
    if TOKEN_FILE:
        MANUAL_MODE = True

    if MANUAL_MODE:
        # Modo manual: validar token y api-server
        if not TOKEN_FILE:
            print(f"{RED}Modo manual requiere: -t <token-file> -a <api-server> [-c <ca.crt>]{NC}")
            show_help()
            sys.exit(1)
        if not os.path.isfile(TOKEN_FILE):
            print(f"{RED}El archivo de token no existe: {TOKEN_FILE}{NC}")
            sys.exit(1)
        if CA_FILE and not os.path.isfile(CA_FILE):
            print(f"{RED}El archivo CA no existe: {CA_FILE}{NC}")
            sys.exit(1)
        if not API_SERVER:
            print(f"{RED}Modo manual requiere especificar el API server con -a <url>{NC}")
            sys.exit(1)

        # Decodificar JWT para extraer SA y namespace si no fueron especificados
        decode_jwt_payload(TOKEN_FILE)

        if not SA_NAME:
            if JWT_SA:
                SA_NAME = JWT_SA
                log_info(f"ServiceAccount detectado del token JWT: {SA_NAME}")
            else:
                log_warn("No se pudo extraer el SA del token. Usando 'manual-sa' por defecto.")
                SA_NAME = "manual-sa"

        if not NAMESPACE:
            if JWT_NS:
                NAMESPACE = JWT_NS
                log_info(f"Namespace detectado del token JWT: {NAMESPACE}")
            else:
                print(f"{RED}No se pudo extraer el namespace del token. Especificalo con -n <namespace>{NC}")
                sys.exit(1)
    else:
        # Modo pod: validar kubeconfig, namespace y pod
        if not KUBECONFIG or not NAMESPACE or not POD:
            print(f"{RED}Faltan parámetros obligatorios. Usa modo pod (-k -n -p) o modo manual (-t -c -n -a).{NC}")
            show_help()
            sys.exit(1)
        if not os.path.isfile(KUBECONFIG):
            print(f"{RED}El archivo kubeconfig no existe: {KUBECONFIG}{NC}")
            sys.exit(1)


# ============================================================================
# Función principal
# ============================================================================
def main():
    global API_SERVER, SA_NAME, OUTPUT_DIR

    print(f"{BLUE}════════════════════════════════════════════════════════════{NC}")
    print(f"{BLUE}              K8S TOKEN EXTRACTOR{NC}")
    print(f"{BLUE}════════════════════════════════════════════════════════════{NC}")
    print()

    parse_args()

    if MANUAL_MODE:
        # --- MODO MANUAL ---
        log_info("Modo: MANUAL (construyendo desde archivos)")

        if not OUTPUT_DIR or OUTPUT_DIR == "./generated_kubeconfigs":
            OUTPUT_DIR = f"./SA_{SA_NAME}"
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        log_info(f"Token file    : {TOKEN_FILE}")
        log_info(f"CA file       : {CA_FILE}")
        log_info(f"Directorio    : {OUTPUT_DIR}")
        if VERBOSE:
            log_info("Modo verbose: activado")
        print()

        load_from_files()
        generate_kubeconfig(API_SERVER)

        # Token Intelligence Report solo en modo verbose
        if VERBOSE:
            show_token_report(TOKEN_FILE, is_file=True)

    else:
        # --- MODO POD ---
        log_info("Modo: POD (extrayendo desde pod en ejecución)")

        check_dependencies()

        if not check_access():
            print()
            log_error("Proceso detenido debido a falta de permisos.")
            print(f"{BLUE}════════════════════════════════════════════════════════════{NC}")
            sys.exit(1)

        # Intentar obtener SA para ajustar directorio de salida
        rc, stdout, _ = run_cmd([
            "kubectl", f"--kubeconfig={KUBECONFIG}", "get", "pod",
            "-n", NAMESPACE, POD, "-o", "jsonpath={.spec.serviceAccountName}",
        ])
        SA_NAME = stdout.strip() if stdout.strip() else "sa"

        if not OUTPUT_DIR or OUTPUT_DIR == "./generated_kubeconfigs":
            OUTPUT_DIR = f"./SA_{SA_NAME}"
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        log_info(f"Kubeconfig    : {KUBECONFIG}")
        log_info(f"Pod           : {POD}")
        log_info(f"Directorio    : {OUTPUT_DIR}")
        if VERBOSE:
            log_info("Modo verbose: activado")
        print()

        extract_from_pod()

        API_SERVER = get_api_server()
        log_info(f"API Server : {API_SERVER}")

        generate_kubeconfig(API_SERVER)

        # Generar reporte del token extraído (solo en modo verbose)
        if VERBOSE and TOKEN:
            decode_jwt_payload(TOKEN, is_file=False)
            show_token_report(TOKEN, is_file=False)

    print()
    log_info("Proceso completado.")

    # Mostrar comandos rápidos
    kc = os.path.join(OUTPUT_DIR, f"kubeconfig_{NAMESPACE}_{SA_NAME}.yaml")
    print()
    print(f"{YELLOW}--- [COMANDOS RÁPIDOS] ---{NC}")
    print(f"  {GREEN}# Reconocimiento{NC}")
    print(f"  kubectl --kubeconfig={kc} auth can-i --list")
    print(f"{BLUE}════════════════════════════════════════════════════════════{NC}")


# ============================================================================
# Ejecutar
# ============================================================================
if __name__ == "__main__":
    main()
