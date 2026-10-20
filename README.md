# Infraestructura de comunicaciones seguras

Proyecto académico en Python para estudiar comunicaciones TCP/TLS, certificados y confianza, autenticación y autorización por roles, auditoría, administración remota por OpenSSH y conceptos de encapsulación tipo IPsec.

**Guía completa de instalación y ejecución para Windows/PowerShell:** [docs/GUIA_PASO_A_PASO_WINDOWS.md](docs/GUIA_PASO_A_PASO_WINDOWS.md). Incluye comandos separados para las terminales del servidor y cliente, generación de certificados, configuración de usuarios, ejecución de pruebas, solución de problemas y evidencia sugerida.

> **Alcance real:** TCP/TLS, validación de certificados, autenticación/autorización, auditoría y la simulación IPsec están implementados en código. SSH se prueba mediante OpenSSH del sistema cuando se configura. La simulación IPsec no es el protocolo IPsec del sistema operativo y no crea una VPN. Los escenarios de VPN de acceso remoto y sitio a sitio requieren gateways y túneles reales que este repositorio no configura. No presentar la simulación como una VPN real.

## 1. Requisitos

- Windows 10/11 con PowerShell o un sistema compatible.
- Python 3.13 o versión compatible con el código y las pruebas.
- Git para clonar y actualizar el repositorio.
- OpenSSL 3.x para generar la PKI de laboratorio.
- OpenSSH Client; OpenSSH Server y una cuenta preparada solo para la prueba de integración SSH.
- No se necesitan dependencias externas de Python: el proyecto usa la biblioteca estándar.

## 2. Instalación

Desde PowerShell:

```powershell
git clone https://github.com/brandguss/infraestructura-comunicaciones-seguras.git
Set-Location infraestructura-comunicaciones-seguras
python --version
```

Si ya tienes el repositorio, entra a su carpeta local en lugar de clonarlo otra vez. Si PowerShell no reconoce `python`, instala Python y activa **Add Python to PATH**; después reinicia la terminal de VS Code.

Comprueba la suite:

```powershell
python -m unittest discover -s tests -p "test*.py" -v
```

Las pruebas que dependen de certificados externos o SSH real se omiten hasta configurar esos requisitos. Una prueba omitida no es una prueba aprobada.

## 3. Inicio rápido: TCP local

Abre dos terminales en la raíz del repositorio.

**Terminal 1 — servidor:**

```powershell
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_server
```

**Terminal 2 — cliente:**

```powershell
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_client "Mensaje TCP de prueba"
```

La respuesta debe comenzar con `RECIBIDO:`. TCP sin cifrar se incluye para comparación académica: no envíes credenciales ni información sensible en este modo. Detén el servidor con `Ctrl+C`.

## 4. Funcionalidades y alcance

| Componente | Implementación | Cómo se demuestra |
|---|---|---|
| Cliente/servidor TCP | Implementado | Eco local con dos terminales. |
| Transporte TLS | Implementado | Cliente y servidor TLS con certificados configurados; TLS 1.2 como mínimo. |
| Confianza y nombre del certificado | Implementado | CA confiable y CA no confiable, más comprobación del nombre/SAN. |
| Creación de PKI de laboratorio | Procedimiento reproducible | Comandos OpenSSL de la guía; los archivos se generan fuera del repositorio. |
| Autenticación | Implementada | Usuarios externos con hashes scrypt y sal por usuario. |
| Autorización | Implementada | El servidor asigna el rol; cada operación tiene permisos definidos. |
| Auditoría | Implementada | Eventos JSON Lines, sin guardar contraseñas. |
| Integración SSH | Prueba de integración con OpenSSH | Requiere host, usuario, clave privada autorizada y host key confiable. |
| Modos transporte/túnel tipo IPsec | Simulación de aplicación | Paquetes JSON simulados, HMAC-SHA256 y control anti-replay; no es IPsec real. |
| VPN de acceso remoto | No se crea túnel real | Se explica la arquitectura y qué componentes externos requiere. |
| VPN sitio a sitio | No se crea túnel real | Se explica la arquitectura; requiere dos gateways, rutas y políticas reales. |
| Pruebas automatizadas | `unittest` | Suite local; las pruebas de integración necesitan preparación externa. |

Esta tabla distingue explícitamente código ejecutable, integración dependiente del entorno, simulación y arquitectura conceptual. La documentación de un escenario no equivale a demostrar un túnel real.

## 5. Estructura del repositorio

```text
src/comunicaciones_seguras/
  config.py             Validación de variables de entorno
  tcp_server.py         Servidor TCP/TLS y procesamiento de solicitudes
  tcp_client.py         Cliente TCP/TLS y operaciones protegidas
  auth.py               Credenciales, roles y autorización
  audit.py              Registro de eventos JSON Lines
  user_setup.py         Preparación interactiva de usuarios
  ipsec_sim.py          Simulación de encapsulación, integridad y anti-replay
  ipsec_key_setup.py    Generación de clave externa para la simulación
tests/
  test_tcp.py
  test_tls.py
  test_auth.py
  test_ssh.py
  test_ipsec_sim.py
docs/
  GUIA_PASO_A_PASO_WINDOWS.md
```

## 6. Configuración y archivos sensibles

La configuración se proporciona mediante variables de entorno para no incrustar rutas ni secretos en el código. Las rutas externas predeterminadas de la guía son:

- PKI de prueba: `%USERPROFILE%\.infraestructura-comunicaciones-seguras\pki`
- Usuarios y auditoría: `%USERPROFILE%\.infraestructura-comunicaciones-seguras\auth`
- Clave de simulación IPsec: `%USERPROFILE%\.infraestructura-comunicaciones-seguras\ipsec`

Variables principales:

| Variable | Uso |
|---|---|
| `TCP_HOST`, `TCP_PORT` | Dirección y puerto de escucha/destino. |
| `COMMUNICATION_MODE` | `tcp` o `tls`. |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | Certificado público y clave privada del servidor TLS. |
| `TLS_CA_FILE`, `TLS_SERVER_NAME` | CA de confianza y nombre esperado por el cliente. |
| `AUTH_USERS_FILE`, `AUDIT_LOG_FILE` | Archivo externo de usuarios y archivo externo de auditoría. |
| `TLS_TEST_CA_FILE`, `TLS_TEST_CERT_FILE`, `TLS_TEST_KEY_FILE`, `TLS_TEST_SERVER_NAME`, `TLS_TEST_UNTRUSTED_CA_FILE` | Material externo requerido por las pruebas TLS correspondientes. |
| `SSH_TEST_ENABLED` | Debe ser `1` para ejecutar la integración SSH. |
| `SSH_TEST_HOST`, `SSH_TEST_USER`, `SSH_TEST_PRIVATE_KEY_FILE`, `SSH_TEST_PORT` | Configuración del servidor OpenSSH de pruebas. |
| `IPSEC_SIM_ENABLED` | `1` activa la simulación de aplicación. |
| `IPSEC_SIM_KEY_FILE`, `IPSEC_SIM_SPI`, `IPSEC_SIM_MODE` | Clave externa, identificador de asociación y modo `transport` o `tunnel`. |

La lista completa, los valores predeterminados y los comandos listos para copiar están en la [guía paso a paso](docs/GUIA_PASO_A_PASO_WINDOWS.md).

## 7. Crear usuarios y probar autorización

La utilidad de preparación solicita las contraseñas de las cuentas de laboratorio `admin`, `operador` y `consulta`. Configura primero las rutas externas:

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
New-Item -ItemType Directory -Force $auth | Out-Null
$env:AUTH_USERS_FILE = Join-Path $auth "users.json"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
python -m src.comunicaciones_seguras.user_setup
```

Las operaciones protegidas deben ejecutarse sobre TLS por defecto. El cliente solicita la contraseña sin mostrarla:

```powershell
python -m src.comunicaciones_seguras.tcp_client --username admin --operation admin_info
python -m src.comunicaciones_seguras.tcp_client --username consulta --operation list_resources
```

La primera operación debe permitirse con credenciales válidas; la segunda debe denegarse por permisos insuficientes. Para que funcione, el servidor debe tener configurados los mismos valores de `AUTH_USERS_FILE` y `AUDIT_LOG_FILE` y debe ejecutarse en modo TLS. Consulta la guía para los comandos completos de ambas terminales.

## 8. Pruebas automatizadas

Suite general:

```powershell
python -m unittest discover -s tests -p "test*.py" -v
```

Suite con PKI externa ya creada:

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:TLS_TEST_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_TEST_CERT_FILE = "$pki\server\server.crt"
$env:TLS_TEST_KEY_FILE = "$pki\server\server.key"
$env:TLS_TEST_SERVER_NAME = "localhost"
$env:TLS_TEST_UNTRUSTED_CA_FILE = "$pki\untrusted-ca\other-ca.crt"
python -m unittest discover -s tests -p "test*.py" -v
```

**Último resultado reportado en esta sesión:** 35 pruebas, 0 fallidas y 2 omitidas. Las omitidas fueron la integración SSH, que requiere habilitación y credenciales reales, y una prueba de certificado no confiable antes de definir su variable de entorno. Después de configurar `TLS_TEST_UNTRUSTED_CA_FILE`, vuelve a ejecutar la suite para comprobar que esa prueba también se ejecute. Este resultado es el resultado reportado previamente, no una afirmación de que todas las pruebas externas se ejecutaron en cada equipo.

## 9. Seguridad y limitaciones

- TCP sin cifrar es solo para mensajes de prueba.
- No desactives la validación del certificado TLS ni la verificación de la clave del host SSH.
- La simulación IPsec utiliza HMAC para integridad/autenticidad y anti-replay; **no cifra la carga y no es una implementación interoperable de IPsec**.
- El repositorio no crea una VPN de acceso remoto ni una VPN sitio a sitio. Para demostrar esas funciones se necesita instalar/configurar un sistema VPN real, dos extremos de red, rutas y reglas de firewall, y verificar tráfico a través del túnel.
- Las claves privadas, claves simétricas, certificados de prueba, usuarios, hashes, sales y auditorías deben permanecer fuera de Git.
- Es un proyecto académico; no está certificado ni auditado para producción.

## 10. Evidencias recomendadas para la entrega

1. TCP: servidor activo y respuesta del cliente.
2. TLS: conexión validada y respuesta del cliente.
3. TLS: rechazo de CA no confiable.
4. Autorización: operación permitida y operación denegada por rol.
5. Auditoría: eventos permitidos/rechazados sin contraseñas.
6. Suite de pruebas con resumen de aprobadas, fallidas y omitidas.
7. Simulación IPsec en transporte/túnel y prueba anti-replay.
8. SSH real solo si se configuró el servidor, usuario, clave y confianza del host.
9. VPN real solo con un túnel externo configurado y comprobado; no usar la simulación como evidencia de túnel.

## 11. Licencia y uso

Este repositorio es un laboratorio académico. No despliegues sus servicios directamente en producción sin un diseño de amenazas, revisión de código, pruebas de seguridad, manejo de secretos, controles operativos y una implementación VPN real si el requisito la exige.
