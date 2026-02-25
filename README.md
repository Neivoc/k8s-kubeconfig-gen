# k8s-kubeconfig-gen

Herramienta de línea de comandos para extraer tokens de ServiceAccount desde pods de Kubernetes y generar archivos kubeconfig listos para usar. Disponible en Bash y Python.

## Descripción

En escenarios de pentesting, auditoría o administración de clústeres Kubernetes, es común necesitar generar un kubeconfig a partir de las credenciales montadas dentro de un pod. Esta herramienta automatiza ese proceso: se conecta al pod vía `kubectl exec`, extrae el token, el certificado CA y el namespace desde `/var/run/secrets/kubernetes.io/serviceaccount/`, y genera un kubeconfig funcional con permisos seguros (600).

También soporta un modo manual donde se construye el kubeconfig a partir de archivos de token y CA ya existentes, sin necesidad de acceso directo al pod.

## Características

- **Dos modos de operación**: extracción directa desde un pod en ejecución o construcción manual desde archivos locales.
- **Decodificación JWT**: analiza el token para extraer automáticamente el ServiceAccount, namespace e información del clúster.
- **Token Intelligence Report**: reporte detallado del token JWT que incluye proveedor cloud (GKE, EKS, AKS, on-premise), identidad Kubernetes, estado de expiración y metadatos de seguridad.
- **Detección automática de cloud provider**: identifica GCP, AWS y Azure a partir del issuer URL del token.
- **Modo inseguro opcional**: si no se proporciona CA, genera el kubeconfig con `insecure-skip-tls-verify: true`.
- **Permisos seguros**: todos los archivos generados se crean con permisos 600.
- **Validación previa**: verifica conectividad al API server, existencia del pod y permisos de exec antes de intentar la extracción.
- **Implementación dual**: misma funcionalidad en Bash (`k8s-kubeconfig-gen.sh`) y Python (`k8s-kubeconfig-gen.py`).

## Requisitos

- `kubectl` configurado y accesible en el PATH
- `base64` (incluido en la mayoría de sistemas Linux/macOS)
- Python 3.6+ (solo para la versión Python, sin dependencias externas)

## Uso

### Modo Pod (extracción desde un pod en ejecución)

```
# Bash
./k8s-kubeconfig-gen.sh -k <kubeconfig> -n <namespace> -p <pod>

# Python
python3 k8s-kubeconfig-gen.py -k <kubeconfig> -n <namespace> -p <pod>
```

### Modo Manual (construcción desde archivos existentes)

```
# Bash
./k8s-kubeconfig-gen.sh -t <token-file> -a <api-server> [-c <ca.crt>] [-n <namespace>] [-s <sa-name>]

# Python
python3 k8s-kubeconfig-gen.py -t <token-file> -a <api-server> [-c <ca.crt>] [-n <namespace>] [-s <sa-name>]
```

### Parámetros

| Parámetro | Descripción |
|-----------|-------------|
| `-k` | Ruta al kubeconfig actual (modo pod) |
| `-n` | Namespace del ServiceAccount |
| `-p` | Nombre del pod (modo pod) |
| `-t` | Ruta al archivo con el token (modo manual) |
| `-c` | Ruta al archivo CA certificate (modo manual, opcional) |
| `-a` | URL del API server (obligatorio en modo manual, opcional en modo pod) |
| `-s` | Nombre del ServiceAccount (si no se especifica, se extrae del JWT) |
| `-x` | Nombre del contexto en el kubeconfig generado |
| `-l` | Nombre del cluster en el kubeconfig generado |
| `-o` | Directorio de salida (por defecto: `./SA_<sa-name>`) |
| `-v` | Modo verbose, muestra el Token Intelligence Report |

### Ejemplos

```
# Extraer credenciales de un pod en producción
./k8s-kubeconfig-gen.sh -k kubeconfig.yaml -n production -p webapp-deploy-7f8b9c6d4-x2k9m

# Extraer con reporte detallado del token
./k8s-kubeconfig-gen.sh -k admin.conf -n monitoring -p prometheus-server-5c8f7d-r4j2p -v

# Construir kubeconfig desde archivos locales
python3 k8s-kubeconfig-gen.py -t token.txt -c ca.crt -n kube-system -a https://10.10.10.1:6443

# Construir sin CA (modo inseguro)
python3 k8s-kubeconfig-gen.py -t token.txt -n default -a https://k8s.example.com:6443 -s deploy-sa
```

## Archivos generados

La herramienta crea un directorio `SA_<service-account-name>/` con los siguientes archivos:

```
SA_<sa-name>/
  kubeconfig_<namespace>_<sa-name>.yaml   # Kubeconfig listo para usar
  token.txt                                # Token del ServiceAccount
  ca.crt                                   # Certificado CA (si aplica)
  namespace.txt                            # Namespace extraído
```

## Token Intelligence Report

Con la opción `-v`, la herramienta genera un reporte detallado del token JWT que incluye:

- **Entorno del clúster**: proveedor cloud detectado (GKE, EKS, AKS o self-hosted), región, proyecto e issuer URL.
- **Identidad Kubernetes**: namespace, ServiceAccount, pod de origen, nodo asignado y UIDs.
- **Estado de seguridad**: audiencia, fechas de creación y expiración, vida útil del token y estado actual (activo, expirado o próximo a expirar).

## Tecnologías

- Bash
- Python 3
- Kubernetes API (kubectl)
- JWT (decodificación sin librerías externas)
