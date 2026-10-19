# Infraestructura de comunicaciones seguras

Proyecto académico incremental para representar una infraestructura de comunicaciones seguras en una pequeña organización.

## Etapas 1 a 4: TCP, TLS, autenticación, auditoría y SSH

El proyecto contiene un servidor y un cliente implementados exclusivamente con la biblioteca estándar de Python. Ambos intercambian texto UTF-8 y una confirmación. Se puede elegir entre TCP sin cifrar, para comparación académica, y TLS real con certificados firmados por una CA de pruebas.

TLS, autenticación, autorización por roles, auditoría y una verificación de administración remota mediante OpenSSH están implementados. IPSec y VPN aún no forman parte del proyecto.

## Requisitos detectados

- Python: `3.13.15` (comando `python`)
- Git: no disponible en el `PATH` durante la inspección
- OpenSSL: `OpenSSL 3.6.5`, en `C:\Program Files\OpenSSL-Win64\bin\openssl.exe`
- OpenSSH Client y OpenSSH Server de Windows: necesarios solo para la prueba de integración SSH opcional.

No se requieren paquetes externos.

## Estructura

```text
src/comunicaciones_seguras/
  config.py       # Configuración desde variables de entorno
  tcp_server.py   # Servidor TCP
  tcp_client.py   # Cliente TCP y TLS
  auth.py         # Usuarios, scrypt y permisos del servidor
  audit.py        # Auditoría JSON Lines externa
  user_setup.py   # Creador interactivo de usuarios de demostración
tests/
  test_tcp.py     # Pruebas automatizadas locales
  test_tls.py     # Pruebas TLS con PKI externa
  test_auth.py    # Pruebas de autenticación, roles y auditoría
  test_ssh.py     # Configuración y prueba real opcional de OpenSSH
```

## Configuración

| Variable | Valor predeterminado | Uso |
| --- | --- | --- |
| `TCP_HOST` | `127.0.0.1` | Dirección en la que escucha el servidor o dirección del servidor para el cliente. |
| `TCP_PORT` | `5000` | Puerto TCP, entre 1 y 65535. |
| `COMMUNICATION_MODE` | `tcp` | Modo `tcp` o `tls`. |
| `TLS_CA_FILE` | — | Ruta externa al certificado público de la CA confiable. Cliente TLS. |
| `TLS_CERT_FILE` | — | Ruta externa al certificado público del servidor. Servidor TLS. |
| `TLS_KEY_FILE` | — | Ruta externa a la clave privada del servidor. Servidor TLS. |
| `TLS_SERVER_NAME` | `TCP_HOST` | Nombre o IP que el cliente valida contra el SAN del certificado. |
| `AUTH_USERS_FILE` | — | Archivo externo JSON con usuarios, sales y hashes scrypt. |
| `AUDIT_LOG_FILE` | — | Archivo externo JSON Lines para eventos de auditoría. |
| `SSH_TEST_ENABLED` | — | Use `1` para habilitar explícitamente la prueba de integración SSH. |
| `SSH_TEST_HOST` | — | Host del servidor OpenSSH de pruebas. |
| `SSH_TEST_USER` | — | Usuario remoto de pruebas. |
| `SSH_TEST_PRIVATE_KEY_FILE` | — | Ruta externa a la clave privada de OpenSSH. |
| `SSH_TEST_PORT` | `22` | Puerto del servidor OpenSSH. |
| `SSH_TEST_TIMEOUT` | `15` | Límite de conexión y ejecución, entre 1 y 60 segundos. |
| `SSH_TEST_KNOWN_HOSTS_FILE` | — | Archivo `known_hosts` externo opcional; si se omite se usa el predeterminado de OpenSSH. |
| `SSH_EXECUTABLE` | `ssh` | Cliente OpenSSH a invocar. |

TLS exige CA explícita, validación del certificado, validación de hostname y TLS 1.2 o superior. No existe un modo para desactivar estas comprobaciones.

## Autenticación, roles y auditoría

Las operaciones protegidas se envían con usuario, contraseña y operación; el cliente no envía un rol. El servidor valida las credenciales mediante `hashlib.scrypt` con una sal aleatoria por usuario y `hmac.compare_digest`, y obtiene el rol exclusivamente de `AUTH_USERS_FILE`.

| Operación | Administrador | Operador | Consulta |
| --- | --- | --- | --- |
| `status` | Sí | Sí | Sí |
| `list_resources` | Sí | Sí | No |
| `admin_info` | Sí | No | No |

Una credencial errónea siempre produce `acceso_denegado`, sin informar si el error fue el usuario o la contraseña. Una configuración ausente, ilegible o sin auditoría disponible rechaza las operaciones protegidas. El flujo de texto simple de la etapa 1 se conserva como eco compatible; no es una operación protegida y no debe usarse para administración.

Prepare rutas externas, nunca dentro del repositorio:

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$env:AUTH_USERS_FILE = Join-Path $auth "users.json"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
python -m src.comunicaciones_seguras.user_setup
```

La utilidad solicita contraseñas sin mostrarlas y solo persiste sales y hashes scrypt. No use `--overwrite` salvo que desee reemplazar deliberadamente el archivo externo. Las claves, hashes, sales y auditorías no deben subirse a GitHub.

## Administración remota segura mediante SSH

Esta etapa integra una **prueba de administración remota** contra un servidor OpenSSH real ya instalado. El proyecto no implementa un servidor SSH en Python, no abre puertos adicionales, ni modifica `sshd_config`, el firewall, las claves autorizadas o los permisos de Windows.

La prueba invoca el cliente OpenSSH con autenticación por clave, `BatchMode=yes`, `PasswordAuthentication=no`, límite de tiempo y `StrictHostKeyChecking=yes`. Por tanto, la clave de host del servidor debe existir previamente en el archivo `known_hosts` elegido. Nunca se usa `StrictHostKeyChecking=no`.

La clave privada debe permanecer fuera del repositorio. No la copie, imprima ni incluya en variables registradas. El patrón `.ssh/` y los nombres convencionales de identidades privadas en la raíz del proyecto se excluyen mediante `.gitignore`; no se excluyen de forma genérica archivos que solo comienzan por `id_`.

Para un equipo Windows configurado con OpenSSH Server, habilite la integración de forma explícita en PowerShell. Ajuste únicamente los valores externos correspondientes a su entorno:

```powershell
$env:SSH_TEST_ENABLED = "1"
$env:SSH_TEST_HOST = "localhost"
$env:SSH_TEST_USER = "brand"
$env:SSH_TEST_PRIVATE_KEY_FILE = Join-Path $env:USERPROFILE ".ssh\id_ed25519_sdi"
$env:SSH_TEST_PORT = "22"
$env:SSH_TEST_TIMEOUT = "15"
# Opcional: use un archivo known_hosts específico ya preparado.
# $env:SSH_TEST_KNOWN_HOSTS_FILE = Join-Path $env:USERPROFILE ".ssh\known_hosts"
python -m unittest tests.test_ssh.SSHIntegrationTests -v
```

El resultado esperado es una ejecución exitosa de `whoami` con salida no vacía. Si falla después de habilitarse, la prueba falla —no se omite— y debe revisarse: servicio OpenSSH Server, puerto, usuario, clave pública autorizada, ruta de clave privada, permisos de la clave y confianza previa de la clave de host. Si `SSH_TEST_ENABLED` no vale `1`, la prueba se marca explícitamente como `skipped` para que la suite general no dependa de infraestructura local.

Ejecute la integración desde la sesión de Windows del usuario que tiene acceso a la clave privada o a su agente SSH. Un entorno automatizado restringido puede no tener permiso de abrir esa clave, incluso si el comando manual funciona en una consola interactiva; la prueba lo informará como `clave privada no disponible para el proceso`, sin mostrar rutas ni secretos. No cambie permisos ni quite la passphrase automáticamente para evitar este error.

Las pruebas de configuración SSH no abren conexiones. La prueba de integración sí ejecuta `whoami`; una comprobación manual equivalente es:

```powershell
ssh -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes -o "ConnectTimeout=$env:SSH_TEST_TIMEOUT" -o NumberOfPasswordPrompts=0 -i $env:SSH_TEST_PRIVATE_KEY_FILE -p $env:SSH_TEST_PORT "$env:SSH_TEST_USER@$env:SSH_TEST_HOST" whoami
```

SSH protege la administración remota del sistema, pero no reemplaza la autenticación, la autorización por roles ni la auditoría de la aplicación. Tampoco es IPSec ni una VPN. El usuario de desarrollo indicado pertenece a administradores de Windows; en producción use una cuenta dedicada con privilegios mínimos y una política de claves separada.

## PKI de pruebas fuera del repositorio

No guarde claves ni certificados de desarrollo dentro de este repositorio. El ejemplo siguiente utiliza un directorio externo. `OPENSSL_EXE` permite indicar otra ruta si `openssl` no está en `PATH`.

```powershell
$env:OPENSSL_EXE = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
$openssl = if (Get-Command openssl -ErrorAction SilentlyContinue) { "openssl" } else { $env:OPENSSL_EXE }
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
New-Item -ItemType Directory -Force "$pki\ca", "$pki\server", "$pki\untrusted-ca" | Out-Null
```

Genere una CA raíz y un certificado de servidor firmado por ella. Los SAN permiten las pruebas locales por hostname e IP.

```powershell
& $openssl genrsa -out "$pki\ca\root-ca.key" 4096
& $openssl req -x509 -new -sha256 -key "$pki\ca\root-ca.key" -days 3650 -out "$pki\ca\root-ca.crt" -subj "/CN=CA raíz académica" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign"
& $openssl genrsa -out "$pki\server\server.key" 2048
& $openssl req -new -key "$pki\server\server.key" -out "$pki\server\server.csr" -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
@"
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
"@ | Set-Content -Encoding ascii "$pki\server\server-extensions.cnf"
& $openssl x509 -req -in "$pki\server\server.csr" -CA "$pki\ca\root-ca.crt" -CAkey "$pki\ca\root-ca.key" -CAcreateserial -out "$pki\server\server.crt" -days 365 -sha256 -extfile "$pki\server\server-extensions.cnf"
```

Para comprobar el rechazo de CA no confiable, cree una CA alternativa (su certificado público no debe firmar el certificado del servidor):

```powershell
& $openssl genrsa -out "$pki\untrusted-ca\other-ca.key" 2048
& $openssl req -x509 -new -sha256 -key "$pki\untrusted-ca\other-ca.key" -days 365 -out "$pki\untrusted-ca\other-ca.crt" -subj "/CN=CA no confiable de pruebas"
```

Las claves `*.key`, las solicitudes, los números de serie y el directorio `pki/` están excluidos por `.gitignore` como barrera adicional, pero la regla principal es que la PKI permanezca fuera del repositorio.

Para una prueba local no es necesario configurar nada. Para usar dos equipos, inicie el servidor con una dirección de enlace accesible (por ejemplo `0.0.0.0`) y use en el cliente la IP real del equipo servidor. Asegúrese de que la red y el firewall permitan el puerto elegido.

## Ejecución TCP sin cifrar

Abra una terminal en la raíz del proyecto e inicie el servidor:

```powershell
python -m src.comunicaciones_seguras.tcp_server
```

En una segunda terminal, ejecute el cliente:

```powershell
python -m src.comunicaciones_seguras.tcp_client "Mensaje de prueba"
```

El cliente debe mostrar `RECIBIDO: Mensaje de prueba`. Para detener el servidor, presione `Ctrl+C`.

Para ejecutar operaciones autenticadas sobre TCP (solo para comparar el riesgo de canal sin cifrar), configure primero las rutas de autenticación en la terminal del servidor y del cliente. Es preferible TLS porque la contraseña viaja como parte de la solicitud de aplicación.

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$env:AUTH_USERS_FILE = Join-Path $auth "users.json"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
python -m src.comunicaciones_seguras.tcp_server
```

En otra terminal:

```powershell
python -m src.comunicaciones_seguras.tcp_client --username consulta --operation status
```

## Ejecución en dos computadoras

En el equipo servidor:

```powershell
$env:TCP_HOST = "0.0.0.0"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_server
```

En el equipo cliente, sustituya la IP por la del servidor:

```powershell
$env:TCP_HOST = "192.0.2.10"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_client "Hola desde otro equipo"
```

## Ejecución TLS local

En la terminal del servidor, use los materiales externos recién creados:

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "$pki\server\server.crt"
$env:TLS_KEY_FILE = "$pki\server\server.key"
python -m src.comunicaciones_seguras.tcp_server
```

En otra terminal, configure la CA y el nombre del SAN esperado:

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_SERVER_NAME = "localhost"
python -m src.comunicaciones_seguras.tcp_client "Mensaje TLS de prueba"
```

Para operaciones protegidas por TLS, agregue las mismas variables externas de autenticación en la terminal del servidor y ejecute el cliente con una operación:

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$env:AUTH_USERS_FILE = Join-Path $auth "users.json"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
# En el servidor, conserve además COMMUNICATION_MODE=tls, TLS_CERT_FILE y TLS_KEY_FILE.
# En el cliente, conserve COMMUNICATION_MODE=tls, TLS_CA_FILE y TLS_SERVER_NAME.
python -m src.comunicaciones_seguras.tcp_client --username admin --operation admin_info
```

Para otro equipo, regenere el certificado con el DNS o IP real del servidor incluido en el SAN y defina `TLS_SERVER_NAME` con ese mismo valor. No sustituya la validación por un certificado autofirmado del servidor.

## Pruebas

Las pruebas usan `unittest`, incluido con Python:

```powershell
python -m unittest discover -s tests -v
```

Las pruebas TCP siempre son locales. Para habilitar las pruebas TLS que requieren PKI externa, antes del comando anterior defina:

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:TLS_TEST_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_TEST_CERT_FILE = "$pki\server\server.crt"
$env:TLS_TEST_KEY_FILE = "$pki\server\server.key"
$env:TLS_TEST_SERVER_NAME = "localhost"
$env:TLS_TEST_UNTRUSTED_CA_FILE = "$pki\untrusted-ca\other-ca.crt"
python -m unittest discover -s tests -v
```

Si falta el material externo, las pruebas TLS de certificado se marcarán como `skipped`, no como aprobadas. La prueba de error de conexión TLS no necesita certificados.

Las pruebas de autenticación crean usuarios, hashes y auditorías solo en un directorio temporal que se elimina al finalizar; no necesitan credenciales externas.

La prueba SSH de integración está deshabilitada por defecto. Ejecute primero sus pruebas unitarias y después habilítela con las variables de la sección SSH:

```powershell
python -m unittest tests.test_ssh.SSHConfigurationTests -v
python -m unittest tests.test_ssh.SSHIntegrationTests -v
python -m unittest discover -s tests -v
```

## Seguridad y siguientes etapas

TCP transmite el contenido en claro; no debe utilizarse con datos sensibles. TLS protege el canal y verifica la identidad del servidor con una CA explícita; la autenticación de aplicación no lo sustituye. SSH se limita a la administración remota y no implementa IPSec ni VPN. Las claves privadas, hashes, sales y auditorías no se versionan ni se suben a GitHub.
