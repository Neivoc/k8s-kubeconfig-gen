#!/bin/bash

# ============================================================================
# K8S TOKEN EXTRACTOR
# ============================================================================
# Extrae token, CA y namespace de un pod y genera un kubeconfig listo para usar
# También puede construir un kubeconfig a partir de archivos de token, CA y namespace
#
# Uso (modo pod):
#   ./k8s-token-extractor.sh -k <kubeconfig> -n <namespace> -p <pod> [opciones]
#
# Uso (modo manual):
#   ./k8s-token-extractor.sh -t <token-file> -c <ca-file> -n <namespace> -a <api-server> [-s <sa-name>]
#
# Ejemplo:
#   ./k8s-token-extractor.sh -k initial-kubeconfig.yaml -n mirror-world -p machine-697bff775f-49qsh
#   ./k8s-token-extractor.sh -t token.txt -c ca.crt -n mirror-world -a https://10.10.10.1:6443 -s my-sa
# ============================================================================

set -euo pipefail

# Colores para output
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

# Valores por defecto
OUTPUT_DIR="./generated_kubeconfigs"
API_SERVER=""
VERBOSE=false
MANUAL_MODE=false
TOKEN_FILE=""
CA_FILE=""
CONTEXT_NAME=""
CLUSTER_NAME=""

# ============================================================================
# Función de ayuda
# ============================================================================
show_help() {
    cat << EOF
${BLUE}K8S Token Extractor - Extrae token, CA y namespace de un pod y genera un kubeconfig${NC}

${YELLOW}MODO 1 - EXTRACCIÓN DESDE POD:${NC}
  $(basename "$0") -k <kubeconfig> -n <namespace> -p <pod> [opciones]

${YELLOW}MODO 2 - CONSTRUCCIÓN MANUAL:${NC}
  $(basename "$0") -t <token-file> -a <api-server> [-c <ca.crt>] [-n <namespace>] [-s <sa-name>] [opciones]

${YELLOW}PARÁMETROS MODO POD:${NC}
  -k <kubeconfig> Ruta al kubeconfig actual (ej: ./kubeconfig.yaml)
  -n <namespace>  Namespace donde está el pod (ej: production)
  -p <pod>        Nombre exacto del pod (ej: webapp-deploy-7f8b9c6d4-x2k9m)

${YELLOW}PARÁMETROS MODO MANUAL:${NC}
  -t <token-file> Ruta al archivo con el token del ServiceAccount
  -c <ca.crt>    Ruta al archivo CA certificate (ca.crt). Si no se especifica, se genera
                 kubeconfig en modo inseguro (insecure-skip-tls-verify: true)
  -n <namespace>  Namespace (si no se especifica, se extrae del token JWT)
  -a <url>       URL del API server (obligatorio en modo manual)
  -s <sa-name>   Nombre del ServiceAccount (si no se especifica, se extrae del token JWT)

${YELLOW}OPCIONES ADICIONALES:${NC}
  -a <url>       URL del API server (en modo pod se obtiene del kubeconfig si no se especifica)
  -x <context>   Nombre del contexto en el kubeconfig (por defecto: context)
  -l <cluster>   Nombre del cluster en el kubeconfig (por defecto: cluster)
  -o <output-dir> Directorio de salida (por defecto: ./SA_<sa-name>)
  -v             Modo verbose (muestra TOKEN INTELLIGENCE REPORT con detalles del JWT)
  -h             Muestra esta ayuda

${YELLOW}EJEMPLOS:${NC}
  # Modo pod: extraer desde un pod en ejecución
  $(basename "$0") -k kubeconfig.yaml -n production -p webapp-deploy-7f8b9c6d4-x2k9m
  $(basename "$0") -k admin.conf -n monitoring -p prometheus-server-5c8f7d-r4j2p -a https://kubernetes.default.svc -v

  # Modo manual: construir desde archivos existentes
  $(basename "$0") -t token.txt -c ca.crt -n production -a https://10.10.10.1:6443
  $(basename "$0") -t /tmp/token -c /tmp/ca.crt -n kube-system -a https://k8s.example.com:6443 -s deploy-sa -o ./output
EOF
}

# ============================================================================
# Parseo de argumentos
# ============================================================================
parse_args() {
    while getopts "k:n:p:a:o:t:c:s:x:l:vh" opt; do
        case $opt in
            k) KUBECONFIG="$OPTARG" ;;
            n) NAMESPACE="$OPTARG" ;;
            p) POD="$OPTARG" ;;
            a) API_SERVER="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            t) TOKEN_FILE="$OPTARG" ;;
            c) CA_FILE="$OPTARG" ;;
            s) SA_NAME="$OPTARG" ;;
            x) CONTEXT_NAME="$OPTARG" ;;
            l) CLUSTER_NAME="$OPTARG" ;;
            v) VERBOSE=true ;;
            h) show_help; exit 0 ;;
            *) echo -e "${RED}Opción inválida${NC}"; show_help; exit 1 ;;
        esac
    done

    # Detectar modo manual: si se proporcionó -t o -c
    if [ -n "$TOKEN_FILE" ]; then
        MANUAL_MODE=true
    fi

    if [ "$MANUAL_MODE" = true ]; then
        # Modo manual: validar token y api-server (CA es opcional)
        if [ -z "$TOKEN_FILE" ]; then
            echo -e "${RED}Modo manual requiere: -t <token-file> -a <api-server> [-c <ca.crt>]${NC}"
            show_help
            exit 1
        fi
        if [ ! -f "$TOKEN_FILE" ]; then
            echo -e "${RED}El archivo de token no existe: $TOKEN_FILE${NC}"
            exit 1
        fi
        if [ -n "$CA_FILE" ] && [ ! -f "$CA_FILE" ]; then
            echo -e "${RED}El archivo CA no existe: $CA_FILE${NC}"
            exit 1
        fi
        if [ -z "$API_SERVER" ]; then
            echo -e "${RED}Modo manual requiere especificar el API server con -a <url>${NC}"
            exit 1
        fi

        # Decodificar JWT para extraer SA y namespace si no fueron especificados
        decode_jwt_payload "$TOKEN_FILE"

        if [ -z "${SA_NAME:-}" ]; then
            if [ -n "$JWT_SA" ]; then
                SA_NAME="$JWT_SA"
                log_info "ServiceAccount detectado del token JWT: $SA_NAME"
            else
                log_warn "No se pudo extraer el SA del token. Usando 'manual-sa' por defecto."
                SA_NAME="manual-sa"
            fi
        fi

        if [ -z "${NAMESPACE:-}" ]; then
            if [ -n "$JWT_NS" ]; then
                NAMESPACE="$JWT_NS"
                log_info "Namespace detectado del token JWT: $NAMESPACE"
            else
                echo -e "${RED}No se pudo extraer el namespace del token. Especificalo con -n <namespace>${NC}"
                exit 1
            fi
        fi

    else
        # Modo pod: validar kubeconfig, namespace y pod
        if [ -z "${KUBECONFIG:-}" ] || [ -z "${NAMESPACE:-}" ] || [ -z "${POD:-}" ]; then
            echo -e "${RED}Faltan parámetros obligatorios. Usa modo pod (-k -n -p) o modo manual (-t -c -n -a).${NC}"
            show_help
            exit 1
        fi
        if [ ! -f "$KUBECONFIG" ]; then
            echo -e "${RED}El archivo kubeconfig no existe: $KUBECONFIG${NC}"
            exit 1
        fi
    fi
}

# ============================================================================
# Decodificar token JWT y extraer campos
# ============================================================================
JWT_SA=""
JWT_NS=""
JWT_DECODED=""

decode_jwt_payload() {
    local token_content="$1"
    local is_file="${2:-true}"
    local token

    if [ "$is_file" = true ]; then
        token=$(cat "$token_content" | tr -d '\r' | tr -d '\n')
    else
        token=$(echo "$token_content" | tr -d '\r' | tr -d '\n')
    fi

    local payload
    payload=$(echo "$token" | cut -d'.' -f2)
    [ -z "$payload" ] && return 1

    # Padding base64url -> base64
    local pad=$(( 4 - ${#payload} % 4 ))
    if [ "$pad" -lt 4 ]; then
        payload="${payload}$(printf '%0.s=' $(seq 1 "$pad"))"
    fi
    payload=$(echo "$payload" | tr '_-' '/+')

    JWT_DECODED=$(echo "$payload" | base64 -d 2>/dev/null)
    [ -z "$JWT_DECODED" ] && return 1

    local sub
    sub=$(echo "$JWT_DECODED" | grep -o '"sub":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$sub" ]; then
        JWT_NS=$(echo "$sub" | awk -F: '{print $(NF-1)}')
        JWT_SA=$(echo "$sub" | awk -F: '{print $NF}')
    fi
}

# Helper: extraer un campo string del JSON decodificado
jwt_field() {
    local field="$1"
    echo "$JWT_DECODED" | grep -o "\"$field\":\"[^\"]*\"" | head -1 | cut -d'"' -f4
}

# Helper: extraer un campo numérico del JSON decodificado
jwt_field_num() {
    local field="$1"
    echo "$JWT_DECODED" | grep -o "\"$field\":[0-9]*" | head -1 | cut -d: -f2
}

# ============================================================================
# Reporte de inteligencia del token JWT
# ============================================================================
show_token_report() {
    local token_source="$1"  # archivo o variable con el token
    local is_file="${2:-true}"

    # Decodificar si no se hizo antes
    if [ -z "$JWT_DECODED" ]; then
        decode_jwt_payload "$token_source" "$is_file"
    fi

    if [ -z "$JWT_DECODED" ]; then
        log_warn "No se pudo decodificar el token JWT para generar el reporte."
        return 1
    fi

    # --- Extraer campos básicos ---
    local iss=$(jwt_field "iss")
    local sub=$(jwt_field "sub")
    local exp=$(jwt_field_num "exp")
    local iat=$(jwt_field_num "iat")
    local nbf=$(jwt_field_num "nbf")
    local jti=$(jwt_field "jti")

    # aud puede ser string o array: "aud":"..." o "aud":["..."]
    local aud
    aud=$(echo "$JWT_DECODED" | grep -oP '"aud":\["\K[^"]*' 2>/dev/null || jwt_field "aud" || true)

    # --- Campos K8s: soportar formato nested y flat ---
    local k8s_ns="" k8s_sa="" k8s_sa_uid="" k8s_pod="" k8s_pod_uid="" k8s_node="" k8s_node_uid=""

    # Formato nested (projected tokens): "kubernetes.io":{"namespace":"X","pod":{"name":"Y"}}
    k8s_ns=$(echo "$JWT_DECODED" | grep -oP '"kubernetes\.io":\{[^}]*"namespace":"\K[^"]*' 2>/dev/null || true)
    k8s_pod=$(echo "$JWT_DECODED" | grep -oP '"pod":\{"name":"\K[^"]*' 2>/dev/null || true)
    k8s_pod_uid=$(echo "$JWT_DECODED" | grep -oP '"pod":\{"name":"[^"]*","uid":"\K[^"]*' 2>/dev/null || true)
    k8s_node=$(echo "$JWT_DECODED" | grep -oP '"node":\{"name":"\K[^"]*' 2>/dev/null || true)
    k8s_node_uid=$(echo "$JWT_DECODED" | grep -oP '"node":\{"name":"[^"]*","uid":"\K[^"]*' 2>/dev/null || true)
    k8s_sa=$(echo "$JWT_DECODED" | grep -oP '"serviceaccount":\{"name":"\K[^"]*' 2>/dev/null || true)
    k8s_sa_uid=$(echo "$JWT_DECODED" | grep -oP '"serviceaccount":\{"name":"[^"]*","uid":"\K[^"]*' 2>/dev/null || true)

    # Fallback: formato flat (legacy tokens): "kubernetes.io/pod/name":"Y"
    [ -z "$k8s_ns" ] && k8s_ns=$(echo "$JWT_DECODED" | grep -oP '"kubernetes\.io/serviceaccount/namespace":"\K[^"]*' 2>/dev/null || true)
    [ -z "$k8s_sa" ] && k8s_sa=$(echo "$JWT_DECODED" | grep -oP '"kubernetes\.io/serviceaccount/service-account\.name":"\K[^"]*' 2>/dev/null || true)
    [ -z "$k8s_sa_uid" ] && k8s_sa_uid=$(echo "$JWT_DECODED" | grep -oP '"kubernetes\.io/serviceaccount/service-account\.uid":"\K[^"]*' 2>/dev/null || true)
    [ -z "$k8s_pod" ] && k8s_pod=$(echo "$JWT_DECODED" | grep -oP '"kubernetes\.io/pod/name":"\K[^"]*' 2>/dev/null || true)
    [ -z "$k8s_node" ] && k8s_node=$(echo "$JWT_DECODED" | grep -oP '"kubernetes\.io/node/name":"\K[^"]*' 2>/dev/null || true)

    # Usar sub como fallback para namespace/sa
    local sa_ns="${k8s_ns:-$JWT_NS}"
    local sa_name="${k8s_sa:-$JWT_SA}"

    # --- Detectar proveedor cloud y extraer info del issuer URL ---
    local cloud_provider="" cloud_service="" cloud_project="" cloud_region="" cluster_name=""

    if echo "$iss" | grep -qi "container.googleapis.com"; then
        cloud_provider="Google Cloud Platform (GCP)"
        cloud_service="Google Kubernetes Engine (GKE)"
        # iss = https://container.googleapis.com/v1/projects/PROJECT/locations/ZONE/clusters/CLUSTER
        cloud_project=$(echo "$iss" | grep -oP 'projects/\K[^/]+' 2>/dev/null || true)
        cloud_region=$(echo "$iss" | grep -oP 'locations/\K[^/]+' 2>/dev/null || true)
        cluster_name=$(echo "$iss" | grep -oP 'clusters/\K[^/]+' 2>/dev/null || true)
    elif echo "$iss" | grep -qi "eks.amazonaws.com\|oidc.eks"; then
        cloud_provider="Amazon Web Services (AWS)"
        cloud_service="Elastic Kubernetes Service (EKS)"
        # iss = https://oidc.eks.REGION.amazonaws.com/id/ID
        cloud_region=$(echo "$iss" | grep -oP 'eks\.\K[a-z]+-[a-z]+-[0-9]+' 2>/dev/null || true)
        cloud_project=$(echo "$iss" | grep -oP 'id/\K[^/]+' 2>/dev/null || true)
    elif echo "$iss" | grep -qi "azmk8s.io\|azure\|login.microsoftonline.com"; then
        cloud_provider="Microsoft Azure"
        cloud_service="Azure Kubernetes Service (AKS)"
        # iss = https://REGION.oic.prod-aks.azure.com/TENANT/ID/
        cloud_region=$(echo "$iss" | grep -oP 'https://\K[a-z]+(?=\.oic\.prod-aks)' 2>/dev/null || true)
    elif echo "$iss" | grep -qi "kubernetes.default\|kubernetes.svc"; then
        cloud_provider="Self-Hosted / On-Premise"
        cloud_service="Kubernetes"
    fi

    # Fallback: extraer region del nombre del nodo si no se obtuvo del issuer
    if [ -z "$cloud_region" ] && [ -n "$k8s_node" ]; then
        cloud_region=$(echo "$k8s_node" | grep -oP '[a-z]+-[a-z]+[0-9]+-[a-z]' 2>/dev/null | head -1 || true)
    fi

    # --- Timestamps ---
    local iat_str="N/A"
    local exp_str="N/A"
    local status=""
    local status_color=""
    local time_detail=""
    local now
    now=$(date +%s)

    if [ -n "$iat" ] && [ "$iat" -gt 0 ] 2>/dev/null; then
        iat_str=$(date -d "@$iat" '+%d-%b-%Y %H:%M:%S UTC' 2>/dev/null || date -r "$iat" '+%d-%b-%Y %H:%M:%S UTC' 2>/dev/null || echo "$iat")
    fi

    if [ -n "$exp" ] && [ "$exp" -gt 0 ] 2>/dev/null; then
        exp_str=$(date -d "@$exp" '+%d-%b-%Y %H:%M:%S UTC' 2>/dev/null || date -r "$exp" '+%d-%b-%Y %H:%M:%S UTC' 2>/dev/null || echo "$exp")

        if [ "$now" -gt "$exp" ]; then
            local expired_ago=$(( now - exp ))
            local days=$(( expired_ago / 86400 ))
            local hours=$(( (expired_ago % 86400) / 3600 ))
            status="EXPIRADO"
            status_color="$RED"
            time_detail="(hace ${days}d ${hours}h)"
        else
            local remaining=$(( exp - now ))
            local days=$(( remaining / 86400 ))
            local hours=$(( (remaining % 86400) / 3600 ))
            if [ "$days" -lt 7 ]; then
                status="ACTIVO - EXPIRA PRONTO"
                status_color="$YELLOW"
            else
                status="ACTIVO"
                status_color="$GREEN"
            fi
            time_detail="(quedan ${days}d ${hours}h)"
        fi
    else
        status="SIN EXPIRACIÓN"
        status_color="$YELLOW"
        time_detail="(token sin fecha de expiración)"
    fi

    # --- Calcular vida útil del token ---
    local token_lifetime="N/A"
    if [ -n "$iat" ] && [ -n "$exp" ] && [ "$iat" -gt 0 ] && [ "$exp" -gt 0 ] 2>/dev/null; then
        local lifetime=$(( exp - iat ))
        local lt_days=$(( lifetime / 86400 ))
        local lt_hours=$(( (lifetime % 86400) / 3600 ))
        token_lifetime="${lt_days}d ${lt_hours}h"
    fi

    # --- Imprimir reporte ---
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          TOKEN INTELLIGENCE REPORT                          ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}--- [ENTORNO DEL CLÚSTER] ---${NC}"
    [ -n "$cloud_provider" ] && echo -e "  PROVEEDOR CLOUD:     ${GREEN}$cloud_provider${NC}"
    [ -n "$cloud_service" ] && echo -e "  SERVICIO:            $cloud_service"
    [ -n "$cloud_project" ] && echo -e "  ID PROYECTO:         $cloud_project"
    [ -n "$cloud_region" ] && echo -e "  ZONA GEOGRÁFICA:     $cloud_region"
    [ -n "$cluster_name" ] && echo -e "  CLUSTER NAME:        $cluster_name"
    [ -n "$iss" ] && echo -e "  ISSUER URL:          $iss"
    [ -n "${API_SERVER:-}" ] && echo -e "  API SERVER URL:      $API_SERVER"
    echo ""
    echo -e "${YELLOW}--- [IDENTIDAD KUBERNETES] ---${NC}"
    [ -n "$sa_ns" ] && echo -e "  NAMESPACE:           ${GREEN}$sa_ns${NC}"
    [ -n "$sa_name" ] && echo -e "  SERVICE ACCOUNT:     ${GREEN}$sa_name${NC}"
    [ -n "$k8s_sa_uid" ] && echo -e "  SA UID:              $k8s_sa_uid"
    [ -n "$k8s_pod" ] && echo -e "  POD ORIGEN:          $k8s_pod"
    [ -n "$k8s_pod_uid" ] && echo -e "  POD UID:             $k8s_pod_uid"
    [ -n "$k8s_node" ] && echo -e "  NODO ASIGNADO:       $k8s_node"
    [ -n "$k8s_node_uid" ] && echo -e "  NODO UID:            $k8s_node_uid"
    [ -n "$sub" ] && echo -e "  SUBJECT COMPLETO:    $sub"
    echo ""
    echo -e "${YELLOW}--- [ESTADO DE SEGURIDAD] ---${NC}"
    [ -n "$aud" ] && echo -e "  AUDIENCIA (aud):     $aud"
    echo -e "  FECHA CREACIÓN:      $iat_str"
    echo -e "  FECHA EXPIRACIÓN:    $exp_str"
    echo -e "  VIDA ÚTIL TOKEN:     $token_lifetime"
    echo -e "  STATUS:              ${status_color}$status $time_detail${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
}

# ============================================================================
# Funciones de logging
# ============================================================================
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_debug() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# ============================================================================
# Verificación de dependencias
# ============================================================================
check_dependencies() {
    local dependencies=("kubectl" "base64" "tr")
    local missing=false

    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Falta dependencia requerida: $cmd"
            missing=true
        fi
    done

    if [ "$missing" = true ]; then
        log_error "Por favor, instala las dependencias faltantes para continuar."
        exit 1
    fi
}

# ============================================================================
# Verificación de conectividad y permisos
# ============================================================================
check_access() {
    log_info "Verificando acceso al clúster..."

    # 1. Verificar si podemos hablar con el API server (autenticación básica)
    if ! kubectl --kubeconfig="$KUBECONFIG" get ns &>/dev/null && ! kubectl --kubeconfig="$KUBECONFIG" auth can-i get pods &>/dev/null; then
         # Si falla auth básica, intentamos ver si al menos conecta
         if ! kubectl --kubeconfig="$KUBECONFIG" cluster-info &>/dev/null; then
             log_error "No se puede conectar al API server. Verifica tu kubeconfig y conectividad."
             return 1
         fi
    fi

    # 2. Verificar si el pod existe específicamente
    if ! kubectl --kubeconfig="$KUBECONFIG" get pod -n "$NAMESPACE" "$POD" &>/dev/null; then
        # Diferenciar si es problema de namespace o del pod
        if ! kubectl --kubeconfig="$KUBECONFIG" get pod -n "$NAMESPACE" &>/dev/null; then
             # Nota: Esto puede fallar si no tiene permisos para listar pods en el NS, pero es una pista
             log_warn "No se pudo verificar el namespace '$NAMESPACE' o no tienes permisos para listar pods en él."
        fi
        log_error "No se encuentra el pod '$POD' en el namespace '$NAMESPACE'."
        log_error "Posibles causas: Nombre incorrecto, namespace incorrecto, o falta de permisos."
        return 1
    fi
    log_info "Conectividad y Pod OK"

    # Verificar permisos específicos requeridos para la extracción (pods/exec)
    log_info "Verificando permisos de extracción..."
    if ! kubectl --kubeconfig="$KUBECONFIG" auth can-i create pods --subresource=exec -n "$NAMESPACE" &>/dev/null; then
        log_error "No tienes permisos para ejecutar comandos (exec) en el namespace $NAMESPACE"
        log_error "   Requerido: create pods/exec"
        log_error "   Sin este permiso, no es posible leer los archivos del pod."
        return 1
    fi
    log_info "Permisos de extracción (exec) OK"

    # Verificar que podemos hacer exec al pod específico (prueba real)
    log_debug "Verificando exec en $NAMESPACE/$POD"
    if ! kubectl --kubeconfig="$KUBECONFIG" exec -n "$NAMESPACE" "$POD" -- true &>/dev/null; then
        log_error "Tienes el permiso teórico, pero falló la conexión al pod $NAMESPACE/$POD"
        log_error "Posibles causas: Pod terminando, problemas de red, o contenedor sin shell/binarios básicos."
        return 1
    fi
    log_info "Acceso real al pod OK"
}

# ============================================================================
# Extraer token, CA y namespace del pod
# ============================================================================
extract_from_pod() {
    log_info "Extrayendo token del pod..."

    TOKEN=$(kubectl --kubeconfig="$KUBECONFIG" exec -n "$NAMESPACE" "$POD" -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | tr -d '\r' | tr -d '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ -z "$TOKEN" ]; then
        log_error "No se pudo extraer el token"
        exit 1
    fi
    log_debug "Token extraído (${#TOKEN} caracteres)"

    log_info "Extrayendo CA certificate..."
    CA=$(kubectl --kubeconfig="$KUBECONFIG" exec -n "$NAMESPACE" "$POD" -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt 2>/dev/null | sed '/^[[:space:]]*$/d' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ -z "$CA" ]; then
        log_error "No se pudo extraer el CA certificate"
        exit 1
    fi
    log_debug "CA extraído (${#CA} caracteres)"

    log_info "Extrayendo namespace del pod..."
    POD_NAMESPACE=$(kubectl --kubeconfig="$KUBECONFIG" exec -n "$NAMESPACE" "$POD" -- cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null | tr -d '\r' | tr -d '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ -z "$POD_NAMESPACE" ]; then
        log_warn "No se pudo extraer el namespace, usando '$NAMESPACE' por defecto"
        POD_NAMESPACE="$NAMESPACE"
    fi
    log_debug "Namespace extraído: $POD_NAMESPACE"

    # Guardar archivos individuales con permisos seguros
    echo "$TOKEN" > "$OUTPUT_DIR/token.txt"
    echo "$CA" > "$OUTPUT_DIR/ca.crt"
    echo "$POD_NAMESPACE" > "$OUTPUT_DIR/namespace.txt"
    
    chmod 600 "$OUTPUT_DIR/token.txt" "$OUTPUT_DIR/ca.crt" "$OUTPUT_DIR/namespace.txt"
    log_info "Archivos guardados en $OUTPUT_DIR/ (permisos 600)"
}

# ============================================================================
# Determinar API server
# ============================================================================
get_api_server() {
    if [ -n "$API_SERVER" ]; then
        log_debug "Usando API server especificado: $API_SERVER"
        echo "$API_SERVER"
        return
    fi

    # Intentar obtener del kubeconfig
    local api=$(kubectl --kubeconfig="$KUBECONFIG" config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
    if [ -n "$api" ]; then
        log_debug "API server obtenido del kubeconfig: $api"
        echo "$api"
        return
    fi

    # Fallback
    log_warn "No se pudo determinar API server, usando https://kubernetes.default.svc"
    echo "https://kubernetes.default.svc"
}

# ============================================================================
# Generar kubeconfig
# ============================================================================
generate_kubeconfig() {
    local api_server="$1"
    local ctx_name="${CONTEXT_NAME:-context}"
    local cls_name="${CLUSTER_NAME:-cluster}"

    # Nombre del archivo de salida
    local output_file="$OUTPUT_DIR/kubeconfig_${NAMESPACE}_${SA_NAME}.yaml"

    log_debug "ServiceAccount identificado: $SA_NAME"

    if [ -n "$CA" ]; then
        # Modo seguro: con certificate-authority-data
        local ca_b64
        ca_b64=$(echo "$CA" | base64 -w0)
        cat > "$output_file" << EOF
apiVersion: v1
kind: Config
clusters:
- name: $cls_name
  cluster:
    server: $api_server
    certificate-authority-data: $ca_b64
contexts:
- name: $ctx_name
  context:
    cluster: $cls_name
    user: $SA_NAME
    namespace: $POD_NAMESPACE
current-context: $ctx_name
users:
- name: $SA_NAME
  user:
    token: $TOKEN
EOF
    else
        # Modo inseguro: sin CA, skip TLS verify
        cat > "$output_file" << EOF
apiVersion: v1
kind: Config
clusters:
- name: $cls_name
  cluster:
    server: $api_server
    insecure-skip-tls-verify: true
contexts:
- name: $ctx_name
  context:
    cluster: $cls_name
    user: $SA_NAME
    namespace: $POD_NAMESPACE
current-context: $ctx_name
users:
- name: $SA_NAME
  user:
    token: $TOKEN
EOF
    fi

    chmod 600 "$output_file"
    log_info "Kubeconfig generado: $output_file (permisos 600)"
}


# ============================================================================
# Función principal
# ============================================================================
# ============================================================================
# Cargar credenciales desde archivos (modo manual)
# ============================================================================
load_from_files() {
    log_info "Cargando token desde archivo: $TOKEN_FILE"
    TOKEN=$(cat "$TOKEN_FILE" | tr -d '\r' | tr -d '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ -z "$TOKEN" ]; then
        log_error "El archivo de token está vacío: $TOKEN_FILE"
        exit 1
    fi
    log_debug "Token cargado (${#TOKEN} caracteres)"

    if [ -n "$CA_FILE" ]; then
        log_info "Cargando CA certificate desde archivo: $CA_FILE"
        CA=$(cat "$CA_FILE" | sed '/^[[:space:]]*$/d' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [ -z "$CA" ]; then
            log_error "El archivo CA está vacío: $CA_FILE"
            exit 1
        fi
        log_debug "CA cargado (${#CA} caracteres)"
    else
        CA=""
        log_warn "Sin CA certificate (-c). Se generará kubeconfig en modo inseguro (insecure-skip-tls-verify)"
        echo ""
        read -rp "  ¿Deseas continuar sin CA certificate? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[yYsS]$ ]]; then
            log_info "Operación cancelada por el usuario."
            exit 0
        fi
    fi

    POD_NAMESPACE="$NAMESPACE"
    log_debug "Namespace: $POD_NAMESPACE"

    # Guardar copias en el directorio de salida con permisos seguros
    echo "$TOKEN" > "$OUTPUT_DIR/token.txt"
    [ -n "$CA" ] && echo "$CA" > "$OUTPUT_DIR/ca.crt"
    echo "$POD_NAMESPACE" > "$OUTPUT_DIR/namespace.txt"

    local files_to_chmod="$OUTPUT_DIR/token.txt $OUTPUT_DIR/namespace.txt"
    [ -n "$CA" ] && files_to_chmod="$files_to_chmod $OUTPUT_DIR/ca.crt"
    chmod 600 $files_to_chmod
    log_info "Archivos copiados en $OUTPUT_DIR/ (permisos 600)"
}

main() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}              K8S TOKEN EXTRACTOR${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo ""

    parse_args "$@"

    if [ "$MANUAL_MODE" = true ]; then
        # --- MODO MANUAL ---
        log_info "Modo: MANUAL (construyendo desde archivos)"

        # Directorio de salida
        if [ -z "$OUTPUT_DIR" ] || [ "$OUTPUT_DIR" == "./generated_kubeconfigs" ]; then
            OUTPUT_DIR="./SA_$SA_NAME"
        fi
        mkdir -p "$OUTPUT_DIR"

        log_info "Token file    : $TOKEN_FILE"
        log_info "CA file       : $CA_FILE"
        log_info "Directorio    : $OUTPUT_DIR"
        [ "$VERBOSE" = true ] && log_info "Modo verbose: activado"
        echo ""

        load_from_files
        generate_kubeconfig "$API_SERVER"

        # Token Intelligence Report solo en modo verbose
        if [ "$VERBOSE" = true ]; then
            show_token_report "$TOKEN_FILE" true
        fi

    else
        # --- MODO POD ---
        log_info "Modo: POD (extrayendo desde pod en ejecución)"

        if ! check_access; then
            echo ""
            log_error "Proceso detenido debido a falta de permisos."
            echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
            exit 1
        fi

        # Intentar obtener SA para ajustar directorio de salida
        SA_NAME=$(kubectl --kubeconfig="$KUBECONFIG" get pod -n "$NAMESPACE" "$POD" -o jsonpath='{.spec.serviceAccountName}' 2>/dev/null || echo "sa")

        # Si el usuario NO especificó un directorio personalizado, usar SA_
        if [ -z "$OUTPUT_DIR" ] || [ "$OUTPUT_DIR" == "./generated_kubeconfigs" ]; then
            OUTPUT_DIR="./SA_$SA_NAME"
        fi
        mkdir -p "$OUTPUT_DIR"

        log_info "Kubeconfig    : $KUBECONFIG"
        log_info "Pod           : $POD"
        log_info "Directorio    : $OUTPUT_DIR"
        [ "$VERBOSE" = true ] && log_info "Modo verbose: activado"
        echo ""

        extract_from_pod

        API_SERVER=$(get_api_server)
        log_info "API Server : $API_SERVER"

        generate_kubeconfig "$API_SERVER"


        # Generar reporte del token extraído (solo en modo verbose)
        if [ "$VERBOSE" = true ] && [ -n "$TOKEN" ]; then
            decode_jwt_payload "$TOKEN" false
            show_token_report "$TOKEN" false
        fi
    fi

    echo ""
    log_info "Proceso completado."

    # Mostrar comandos rápidos para el pentester
    local kc="$OUTPUT_DIR/kubeconfig_${NAMESPACE}_${SA_NAME}.yaml"
    echo ""
    echo -e "${YELLOW}--- [COMANDOS RÁPIDOS] ---${NC}"
    echo -e "  ${GREEN}# Reconocimiento${NC}"
    echo -e "  kubectl --kubeconfig=$kc auth can-i --list"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
}

# ============================================================================
# Ejecutar
# ============================================================================
main "$@"
