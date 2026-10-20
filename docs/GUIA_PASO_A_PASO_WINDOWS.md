# Guía paso a paso para Windows y PowerShell

Esta guía usa Windows, PowerShell y una sola computadora para las pruebas locales. Todos los comandos se ejecutan desde la carpeta raíz del repositorio. No pegues claves privadas ni contraseñas en el código ni las subas a GitHub.

## 1. Abrir el proyecto y comprobar Python

Abre dos terminales de PowerShell en VS Code. En ambas, cambia a la carpeta del proyecto:

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
python --version
git status --short
```

Se requiere Python 3.13 o una versión compatible. Si `python` no se reconoce, instala Python desde python.org y marca **Add Python to PATH**; después cierra y vuelve a abrir VS Code. El comando `git status --short` debe mostrar los cambios locales, si existen.

No hace falta instalar paquetes de Python: el proyecto usa la biblioteca estándar. Comprueba que las pruebas se descubren:

```powershell
python -m unittest discover -s tests -p "test*.py" -v
```

## 2. Preparar las carpetas externas

Los certificados, las claves, el archivo de usuarios y la auditoría se guardan fuera del repositorio:

```powershell
$base = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras"
$pki = Join-Path $base "pki"
$auth = Join-Path $base "auth"
New-Item -ItemType Directory -Force "$pki\ca", "$pki\server", "$pki\untrusted-ca", $auth | Out-Null
```

No elimines ni reemplaces claves privadas que ya uses. Los siguientes pasos crean archivos nuevos y fallarán si OpenSSL no está disponible o una ruta ya contiene archivos con el mismo nombre.

## 3. Crear CA y certificado TLS de servidor

Instala OpenSSL 3.x si no lo tienes. Si el comando `openssl` no está en PATH, ajusta la ruta de `$env:OPENSSL_EXE` al ejecutable instalado:

```powershell
$env:OPENSSL_EXE = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
$openssl = if (Get-Command openssl -ErrorAction SilentlyContinue) { "openssl" } else { $env:OPENSSL_EXE }
& $openssl version
```

Genera una CA de laboratorio y una clave/certificado de servidor con SAN para `localhost` y `127.0.0.1`:

```powershell
& $openssl genrsa -out "$pki\ca\root-ca.key" 4096
& $openssl req -x509 -new -sha256 -key "$pki\ca\root-ca.key" -days 3650 -out "$pki\ca\root-ca.crt" -subj "/CN=CA raiz academica" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign"
& $openssl genrsa -out "$pki\server\server.key" 2048
& $openssl req -new -key "$pki\server\server.key" -out "$pki\server\server.csr" -subj "/CN=localhost"
@"
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
"@ | Set-Content -Encoding ascii "$pki\server\server-extensions.cnf"
& $openssl x509 -req -in "$pki\server\server.csr" -CA "$pki\ca\root-ca.crt" -CAkey "$pki\ca\root-ca.key" -CAcreateserial -out "$pki\server\server.crt" -days 365 -sha256 -extfile "$pki\server\server-extensions.cnf"
```

Crea otra CA independiente para probar el rechazo de confianza:

```powershell
& $openssl genrsa -out "$pki\untrusted-ca\other-ca.key" 2048
& $openssl req -x509 -new -sha256 -key "$pki\untrusted-ca\other-ca.key" -days 365 -out "$pki\untrusted-ca\other-ca.crt" -subj "/CN=CA no confiable de pruebas"
```

Comprueba que existan los archivos públicos y privados esperados:

```powershell
Get-ChildItem "$pki\ca", "$pki\server", "$pki\untrusted-ca"
```

Los archivos `.key` son secretos. No los compartas ni los incluyas en capturas públicas.

## 4. Ejecutar TCP sin cifrar (dos terminales)

Este modo solo sirve para mostrar el eco de mensajes de prueba. No envíes contraseñas ni información privada por TCP sin cifrar.

**Terminal 1 — servidor:**

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_server
```

Déjala abierta mientras haces la prueba.

**Terminal 2 — cliente:**

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_client "Mensaje TCP de prueba"
```

Debe aparecer una respuesta que comienza con `RECIBIDO:`. Para detener el servidor, usa `Ctrl+C` en la Terminal 1.

## 5. Ejecutar TLS validando el certificado (dos terminales)

**Terminal 1 — servidor TLS:**

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "$pki\server\server.crt"
$env:TLS_KEY_FILE = "$pki\server\server.key"
python -m src.comunicaciones_seguras.tcp_server
```

**Terminal 2 — cliente TLS:**

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_SERVER_NAME = "localhost"
python -m src.comunicaciones_seguras.tcp_client "Mensaje TLS de prueba"
```

El cliente debe informar que la conexión TLS está validada y recibir el eco. Si aparece un error de certificado, revisa la ruta de la CA y que el nombre usado por el cliente coincida con el SAN del certificado. No desactives la validación TLS para ocultar el error.

## 6. Preparar usuarios, roles y auditoría

Ejecuta esta preparación una sola vez (o conserva el archivo si ya lo creaste):

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$env:AUTH_USERS_FILE = Join-Path $auth "users.json"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
python -m src.comunicaciones_seguras.user_setup
```

Se solicitará crear y confirmar una contraseña para cada cuenta de laboratorio: `admin`, `operador` y `consulta`. No se muestran las contraseñas mientras las escribes.

Para probar operaciones protegidas, reinicia el servidor TLS de la sección anterior con estas variables en la **Terminal 1**, antes de ejecutarlo:

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$env:AUTH_USERS_FILE = Join-Path $auth "users.json"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "$pki\server\server.crt"
$env:TLS_KEY_FILE = "$pki\server\server.key"
python -m src.comunicaciones_seguras.tcp_server
```

En la **Terminal 2**, conserva la configuración TLS del cliente y ejecuta:

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$env:AUTH_USERS_FILE = Join-Path $auth "users.json"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
python -m src.comunicaciones_seguras.tcp_client --username admin --operation admin_info
python -m src.comunicaciones_seguras.tcp_client --username consulta --operation list_resources
```

La primera operación debe autorizarse si escribes la contraseña correcta. La segunda debe denegarse por permisos insuficientes: el rol consulta no tiene permiso para listar recursos. Revisa los eventos generados en `$auth\audit.jsonl`; el archivo no debe contener contraseñas.

## 7. Probar rechazo de certificados y ejecutar la suite completa

Esta sección necesita que hayas creado los certificados en el paso 3. Define estas variables en la misma terminal donde ejecutarás las pruebas:

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:TLS_TEST_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_TEST_CERT_FILE = "$pki\server\server.crt"
$env:TLS_TEST_KEY_FILE = "$pki\server\server.key"
$env:TLS_TEST_SERVER_NAME = "localhost"
$env:TLS_TEST_UNTRUSTED_CA_FILE = "$pki\untrusted-ca\other-ca.crt"
python -m unittest discover -s tests -p "test*.py" -v
```

El resultado esperado para las pruebas automatizadas es cero fallos. Si SSH no está habilitado, su prueba de integración aparecerá como omitida por diseño. Una prueba omitida no equivale a una prueba aprobada.

## 8. Configurar y probar la simulación educativa tipo IPsec

**Importante:** este módulo simula formato de paquete, modos transporte/túnel, HMAC y anti-replay dentro de la aplicación. No crea una interfaz de red, no cifra la carga y no establece un túnel IPsec interoperable.

En una terminal, crea una clave externa nueva (el comando no sobrescribe una existente):

```powershell
$ipsec = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\ipsec"
New-Item -ItemType Directory -Force $ipsec | Out-Null
$env:IPSEC_SIM_KEY_FILE = Join-Path $ipsec "ipsec_sim_key.json"
python -m src.comunicaciones_seguras.ipsec_key_setup
```

Para usar la simulación con el cliente y servidor, configura **en ambas terminales** la misma clave y el mismo SPI/modo. En el servidor TLS (Terminal 1):

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$ipsec = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\ipsec"
$env:IPSEC_SIM_ENABLED = "1"
$env:IPSEC_SIM_KEY_FILE = Join-Path $ipsec "ipsec_sim_key.json"
$env:IPSEC_SIM_SPI = "LAB-01"
$env:IPSEC_SIM_MODE = "transport"
$env:AUTH_USERS_FILE = Join-Path $auth "users.json"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "$pki\server\server.crt"
$env:TLS_KEY_FILE = "$pki\server\server.key"
python -m src.comunicaciones_seguras.tcp_server
```

En el cliente (Terminal 2), configura los mismos valores de IPsec y TLS (además de la CA confiable):

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$ipsec = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\ipsec"
$env:IPSEC_SIM_ENABLED = "1"
$env:IPSEC_SIM_KEY_FILE = Join-Path $ipsec "ipsec_sim_key.json"
$env:IPSEC_SIM_SPI = "LAB-01"
$env:IPSEC_SIM_MODE = "transport"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_SERVER_NAME = "localhost"
python -m src.comunicaciones_seguras.tcp_client "Paquete de simulación"
```

Para estudiar el modo túnel, detén el servidor y cambia `IPSEC_SIM_MODE` a `tunnel` tanto en el servidor como en el cliente antes de reiniciarlos. La misma configuración debe usarse en ambos extremos. Ejecuta las pruebas específicas con:

```powershell
python -m unittest discover -s tests -p "test_ipsec_sim.py" -v
```

## 9. Integración SSH real con OpenSSH (opcional)

La prueba de integración usa el cliente OpenSSH instalado en Windows y necesita un servidor SSH accesible, un usuario permitido, autenticación por clave y una clave de host confiable en `known_hosts`. Tener `sshd` ejecutándose no garantiza que la prueba pase: la cuenta debe aceptar la clave pública correspondiente.

Genera una clave dedicada para este laboratorio (si no existe):

```powershell
$sshDir = Join-Path $env:USERPROFILE ".ssh"
New-Item -ItemType Directory -Force $sshDir | Out-Null
$key = Join-Path $sshDir "id_ed25519_sdi"
if (-not (Test-Path $key)) { ssh-keygen -t ed25519 -f $key -C "sdi-lab" }
```

Instala la clave pública en el archivo `authorized_keys` del usuario de destino y verifica manualmente que puedes conectar sin contraseña interactiva y sin omitir la verificación del host. Para una prueba local, la clave pública debe autorizarse en la cuenta local a la que te conectarás. No configures `StrictHostKeyChecking=no`.

Cuando la conexión de clave esté preparada, define:

```powershell
$env:SSH_TEST_ENABLED = "1"
$env:SSH_TEST_HOST = "localhost"
$env:SSH_TEST_USER = "$env:USERNAME"
$env:SSH_TEST_PRIVATE_KEY_FILE = Join-Path $env:USERPROFILE ".ssh\id_ed25519_sdi"
$env:SSH_TEST_PORT = "22"
$env:SSH_TEST_TIMEOUT = "15"
python -m unittest tests.test_ssh.SSHIntegrationTests -v
```

Si no se ha preparado la clave, el usuario remoto o la confianza del host, deja la prueba deshabilitada; la suite de pruebas unitarias de configuración seguirá siendo ejecutable. No es seguro desactivar la comprobación de identidad del servidor solo para que pase el test.

## 10. Ejecución desde dos computadoras de la misma red

La prueba local anterior usa `127.0.0.1`, que solo es accesible desde la misma computadora. Para una prueba entre equipos:

1. En la computadora servidor, elige una IP privada fija o reservada en el router.
2. Configura `TCP_HOST=0.0.0.0` en el servidor para escuchar en interfaces IPv4 locales y conserva el puerto `5001` para TLS.
3. En el firewall de Windows, permite el puerto TCP solo en el perfil/red privada y desde la IP cliente esperada. No desactives el firewall.
4. El cliente configura `TCP_HOST` con la IP real del servidor y `TLS_SERVER_NAME` con un nombre que figure en el SAN del certificado. Si se conecta por IP, el certificado debe incluir esa IP como SAN.
5. Copia al cliente solo el certificado público de la CA (`root-ca.crt`), nunca la clave privada de la CA ni la clave privada del servidor.
6. Ejecuta primero la prueba TLS normal; luego la prueba con CA no confiable. Documenta el resultado y la IP/puerto utilizados.

No expongas el puerto a Internet ni uses la CA de laboratorio para sistemas reales.

## 11. VPN de acceso remoto y VPN sitio a sitio: diferencia importante

El repositorio no configura túneles VPN reales. La simulación IPsec de la sección 8 es código Python de nivel aplicación y no equivale a IPsec del sistema operativo. Para demostrar una VPN real necesitas un software/gateway VPN, configuración de interfaces y rutas, claves/certificados, reglas de firewall y dos extremos de red independientes. La VPN de acceso remoto conecta un cliente individual a una red; la VPN sitio a sitio conecta dos redes detrás de gateways.

Una prueba de túnel no se puede demostrar únicamente con el eco TCP ni con la simulación. No se presenta este proyecto como VPN real hasta que se configure un gateway real y se compruebe conectividad entre las redes a través del túnel. Las plantillas de configuración deben adaptarse a las redes reales, sin publicar claves privadas ni PSK.

## 12. Qué evidencia guardar para la entrega

- Captura del servidor TCP escuchando y el cliente recibiendo `RECIBIDO:`.
- Captura del servidor TLS y del cliente mostrando conexión TLS validada.
- Resultado de prueba con CA no confiable rechazada.
- Salida de operaciones protegidas permitida y denegada según rol.
- Fragmento de auditoría sin contraseñas ni datos sensibles.
- Resultado de `python -m unittest discover -s tests -p "test*.py" -v`, incluyendo las pruebas omitidas y su motivo.
- Salida de pruebas IPsec simuladas.
- Resultado de SSH real solo si se configuró clave, usuario y host.
- Para VPN real, captura del estado del túnel y prueba de conectividad entre subredes; no sustituirla por una captura de la simulación.

## 13. Solución de problemas frecuentes

| Síntoma | Comprobación |
|---|---|
| `python` no se reconoce | Reinstala Python con PATH habilitado y reinicia la terminal de VS Code. |
| `Address already in use` | Otra ejecución ocupa el puerto. Detén el proceso anterior o usa otro `TCP_PORT` en ambos extremos. |
| `Connection refused` | Confirma que el servidor sigue ejecutándose y que el cliente usa la misma IP y puerto. |
| Error TLS de CA | Revisa `TLS_CA_FILE` y que sea el certificado público de la CA que firmó el servidor. |
| Error de nombre TLS | `TLS_SERVER_NAME` debe coincidir con DNS/IP del SAN del certificado. |
| Operación protegida denegada por configuración | Configura `AUTH_USERS_FILE` y `AUDIT_LOG_FILE` en el servidor y reinícialo. |
| Prueba TLS omitida | Define las variables `TLS_TEST_*` del paso 7 en la terminal donde ejecutas unittest. |
| Prueba SSH omitida | Es normal mientras `SSH_TEST_ENABLED` no sea `1`. Para habilitarla, completa todo el paso 9. |
| Simulación rechazada | Cliente y servidor deben usar la misma clave, SPI y modo; revisa también el archivo de auditoría. |

## 14. Cierre seguro

Detén los servidores con `Ctrl+C`. Comprueba qué cambios están pendientes antes de publicar:

```powershell
git status --short
git diff --check
git diff
```

Antes de hacer commit, revisa que no haya archivos `.key`, `.pem`, usuarios, auditorías ni claves de simulación dentro del repositorio. Esta guía describe un laboratorio académico; no es una certificación de seguridad ni una receta de despliegue en producción.
