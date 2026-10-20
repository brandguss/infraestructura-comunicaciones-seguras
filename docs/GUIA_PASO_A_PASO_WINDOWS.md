# Guía paso a paso para Windows y PowerShell

Esta guía lleva el proyecto desde la preparación de Windows hasta la comprobación de cada requisito: TCP frente a TLS, PKI, usuarios y auditoría, IPsec simulado, SSH real, las dos VPN simuladas y la prueba entre dos computadoras. Cada bloque explica para qué sirve, qué debe verse en pantalla y cómo interpretar un error.

## Cómo seguir la demostración

La guía está organizada para que puedas seguirla mientras presentas el proyecto. En cada prueba identifica **qué estamos comprobando**, **en qué terminal ejecutar cada comando**, **qué resultado debe aparecer** y **qué demuestra ese resultado**.

- **Terminal 1 — servidor:** inicia el servicio y debe permanecer abierta mientras el cliente se conecta. No ejecutes los comandos del cliente en esta terminal.
- **Terminal 2 — cliente:** envía el mensaje o la solicitud al servidor y muestra la respuesta o el rechazo esperado.
- **Terminal 3 — pruebas y revisión:** úsala para ejecutar `unittest`, consultar `audit.jsonl` o revisar registros cuando no necesites que esa terminal mantenga otro proceso.
- **Importante en PowerShell:** las variables `$env:...` solo existen en la terminal donde las definiste. Si un paso necesita una variable, vuelve a definirla en la terminal indicada; no supongas que se comparte con otra ventana.
- **Antes de avanzar:** compara la salida con el resultado esperado. Si no coincide, usa la sección 12 de solución de problemas y no presentes la prueba como aprobada.

Los comandos y salidas de esta guía describen el resultado esperado; deben ejecutarse en tu equipo para confirmar el funcionamiento real. Una prueba omitida (`skipped`) no es una prueba aprobada.

Los archivos con claves, usuarios y registros se guardan fuera del repositorio (en `%USERPROFILE%\.infraestructura-comunicaciones-seguras`) para que no terminen publicados en GitHub. Las secciones 1 a 8 se hacen en orden; las secciones 9, 10 y 11 son independientes entre sí.

## 1. Descargar el proyecto y comprobar Python

Si todavía no tienes el proyecto en tu computadora, abre PowerShell y ejecuta estos comandos. Se descargará una copia en la carpeta Documentos del usuario. Si ya lo descargaste, omite el comando `git clone` y usa la ruta donde guardaste el repositorio.

```powershell
Set-Location "$env:USERPROFILE\Documents"
git clone https://github.com/brandguss/infraestructura-comunicaciones-seguras.git
$project = Join-Path $env:USERPROFILE "Documents\infraestructura-comunicaciones-seguras"
Set-Location $project
python --version
git status --short
```

**Resultado esperado:** `git clone` termina sin errores y crea la carpeta del proyecto; `python --version` muestra Python 3.12 o superior. `git status --short` puede no mostrar nada si no hay cambios locales. Si ya tienes el proyecto en otra ubicación, sustituye la ruta asignada a `$project` por la carpeta real del repositorio.

Abre dos terminales de PowerShell en VS Code. En cada terminal nueva, entra a la carpeta del proyecto antes de ejecutar los comandos de los siguientes pasos:

```powershell
$project = Join-Path $env:USERPROFILE "Documents\infraestructura-comunicaciones-seguras"
Set-Location $project
```

Si `python` no se reconoce, instala Python desde python.org y marca **Add Python to PATH**; después cierra y vuelve a abrir VS Code. No necesitas instalar paquetes externos de Python para ejecutar las pruebas actuales, porque se utiliza la biblioteca estándar.

El siguiente comando busca los archivos de prueba dentro de `tests` y ejecuta cada caso encontrado. Sirve como primera comprobación: si falla aquí, conviene resolver ese error antes de iniciar servidores o configurar la red.

```powershell
python -m unittest discover -s tests -p "test*.py" -v
```

## 2. Preparar las carpetas externas

Se crea una carpeta de trabajo dentro de tu perfil de Windows para separar los archivos privados del código fuente. `$pki` contendrá los certificados de la autoridad certificadora y del servidor; `$auth` contendrá las cuentas y el registro de auditoría. Así se pueden regenerar los archivos del laboratorio sin mezclarlos con el código que se sube a GitHub.

```powershell
$base = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras"
$pki = Join-Path $base "pki"
$auth = Join-Path $base "auth"
New-Item -ItemType Directory -Force "$pki\ca", "$pki\server", "$pki\untrusted-ca", $auth | Out-Null
```

No elimines ni reemplaces claves privadas que ya uses. Los siguientes pasos crean archivos nuevos y fallarán si OpenSSL no está disponible o una ruta ya contiene archivos con el mismo nombre.

## 3. Crear CA y certificado TLS de servidor

OpenSSL crea las claves y certificados que TLS necesita para demostrar la identidad del servidor. El primer bloque intenta usar `openssl` si Windows ya lo reconoce; si no, utiliza la ruta indicada en `$env:OPENSSL_EXE`. La salida de `openssl version` debe mostrar una versión instalada. Si el comando no encuentra el archivo, corrige la ruta antes de continuar.

```powershell
$env:OPENSSL_EXE = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
$openssl = if (Get-Command openssl -ErrorAction SilentlyContinue) { "openssl" } else { $env:OPENSSL_EXE }
& $openssl version
```

En este paso se crea una autoridad certificadora local (CA) y se utiliza para firmar el certificado del servidor. El archivo `root-ca.key` es la clave privada de la CA; el archivo `root-ca.crt` es el certificado público que el cliente utilizará para confiar en el servidor. `server.key` identifica al servidor, y `server.crt` es el certificado que se presenta durante TLS. El SAN incluye `localhost` y `127.0.0.1` para que el cliente pueda verificar el nombre con el que se conecta. La comprobación previa evita reemplazar claves existentes por accidente.

```powershell
$protectedFiles = @("$pki\\ca\\root-ca.key", "$pki\\ca\\root-ca.crt", "$pki\\server\\server.key", "$pki\\server\\server.csr", "$pki\\server\\server.crt", "$pki\\untrusted-ca\\other-ca.key", "$pki\\untrusted-ca\\other-ca.crt")
$existingFiles = $protectedFiles | Where-Object { Test-Path $_ }
if ($existingFiles) { throw "Ya existen archivos PKI; no los sobrescribas. Usa una carpeta de laboratorio nueva o revisa los archivos existentes." }
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

Se genera una segunda CA que no es la que firmó el certificado del servidor. Más adelante se utiliza para comprobar que el cliente rechaza certificados emitidos por una autoridad desconocida. Esta prueba es importante porque una conexión TLS no debe aceptarse solamente porque el servidor responda; el cliente también debe comprobar quién firmó el certificado.

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

Esta primera ejecución comprueba que cliente y servidor pueden intercambiar datos por TCP. En la terminal del servidor se configura el puerto `5000` y se deja el proceso esperando conexiones; el cliente se conecta al mismo puerto y envía un mensaje. El resultado correcto es una respuesta que empieza con `RECIBIDO:`. Esta prueba comprueba conectividad y manejo básico de mensajes, pero no cifra el contenido.

**Terminal 1 — servidor:**

```powershell
$project = Join-Path $env:USERPROFILE "Documents\infraestructura-comunicaciones-seguras"
Set-Location $project
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_server
```

Déjala abierta mientras haces la prueba.

**Terminal 2 — cliente:**

```powershell
$project = Join-Path $env:USERPROFILE "Documents\infraestructura-comunicaciones-seguras"
Set-Location $project
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_client "Mensaje TCP de prueba"
```

Debe aparecer una respuesta que comienza con `RECIBIDO:`. Para detener el servidor, usa `Ctrl+C` en la Terminal 1.

## 5. Ejecutar TLS validando el certificado (dos terminales)

**Terminal 1 — servidor TLS:**

```powershell
$project = Join-Path $env:USERPROFILE "Documents\infraestructura-comunicaciones-seguras"
Set-Location $project
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
$project = Join-Path $env:USERPROFILE "Documents\infraestructura-comunicaciones-seguras"
Set-Location $project
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_SERVER_NAME = "localhost"
python -m src.comunicaciones_seguras.tcp_client "Mensaje TLS de prueba"
```

Esta segunda prueba repite el intercambio, ahora con TLS. El servidor utiliza `server.crt` y `server.key`; el cliente utiliza `root-ca.crt` para comprobar la firma y `localhost` para verificar el nombre del servidor. La conexión se considera correcta cuando el cliente valida el certificado y recibe el mensaje de respuesta. Si aparece un error de CA, revisa qué certificado se está usando; si aparece un error de nombre, comprueba el SAN. No se debe quitar la validación para hacer desaparecer el error, porque esa validación es precisamente lo que se está comprobando.

## 6. Preparar usuarios, roles y auditoría

Ejecuta esta preparación una sola vez (o conserva el archivo si ya lo creaste):

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$env:AUTH_USERS_FILE = Join-Path $auth "users.json"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
python -m src.comunicaciones_seguras.user_setup
```

Esta utilidad prepara tres cuentas de prueba con diferentes permisos. Escribe y confirma las contraseñas cuando la herramienta las solicite; PowerShell no mostrará los caracteres. Los datos se guardan en `users.json`, fuera del repositorio. El servidor y el cliente deben apuntar al mismo archivo de usuarios para que las credenciales creadas coincidan con las que se validan durante las pruebas.

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

Con el servidor TLS reiniciado y las rutas de usuarios y auditoría configuradas, la primera orden inicia sesión como `admin` y solicita una operación administrativa. Debe ser aceptada si se introduce la contraseña correcta. La segunda intenta una operación que el rol `consulta` no tiene permitida y debe ser rechazada. Esta diferencia comprueba que el servidor decide los permisos según el rol y no solo según el nombre que envía el cliente. Al final, abre el archivo `audit.jsonl` para confirmar que quedaron eventos de aceptación y rechazo; revisa que no se registren contraseñas.

## 7. Probar rechazo de certificados y ejecutar la suite completa

Las pruebas TLS necesitan rutas hacia los certificados que acabas de crear. Estas variables se definen en la terminal desde la que ejecutarás `unittest`; no se comparten automáticamente entre terminales de PowerShell. Al indicar también la CA no confiable, se habilita la prueba que debe fallar de forma controlada cuando el cliente no confía en la autoridad que firma un certificado.

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

## 8. Simulación de IPsec: modo transporte, modo túnel y anti-replay

Este componente representa los conceptos de IPsec dentro del programa Python: cada mensaje viaja en un paquete con SPI y número de secuencia, protegido con un HMAC que detecta cualquier cambio, y el receptor mantiene una ventana anti-replay que descarta paquetes repetidos. No cifra el contenido (el HMAC garantiza integridad y autenticidad, no confidencialidad) y no crea una interfaz de red del sistema operativo, así que no es un túnel IPsec real.

Los dos modos se distinguen por la estructura del paquete:

| Modo | Qué contiene el paquete |
|---|---|
| `transport` | Un solo encabezado con la carga (`payload_b64`): se protege el mensaje entre los dos extremos. |
| `tunnel` | Un encabezado externo (`outer`, gateway a gateway) y un paquete interno completo (`inner`, con origen, destino y carga): se encapsula un paquete dentro de otro. |

Crea una clave externa nueva (el comando no sobrescribe una existente):

```powershell
$ipsec = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\ipsec"
New-Item -ItemType Directory -Force $ipsec | Out-Null
$env:IPSEC_SIM_KEY_FILE = Join-Path $ipsec "ipsec_sim_key.json"
python -m src.comunicaciones_seguras.ipsec_key_setup
```

En la **Terminal 1** inicia el servidor TLS con la simulación activa. Para probar el modo túnel, detén el servidor, cambia `IPSEC_SIM_MODE` a `tunnel` en ambas terminales y vuelve a empezar.

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

En la **Terminal 2** configura los mismos valores de IPsec y TLS, y envía el primer paquete:

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$ipsec = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\ipsec"
$env:IPSEC_SIM_ENABLED = "1"
$env:IPSEC_SIM_KEY_FILE = Join-Path $ipsec "ipsec_sim_key.json"
$env:IPSEC_SIM_SPI = "LAB-01"
$env:IPSEC_SIM_MODE = "transport"
$env:IPSEC_SIM_SEQUENCE_START = "1"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_SERVER_NAME = "localhost"
python -m src.comunicaciones_seguras.tcp_client "Paquete de simulación"
```

**Resultado esperado:** `RECIBIDO: ...`, porque el servidor aceptó el paquete.

### Demostración de replay con el cliente y el servidor

Cada ejecución del cliente es un proceso nuevo y su contador de secuencia empieza en `IPSEC_SIM_SEQUENCE_START`. Mientras el servidor siga encendido, recuerda los números que ya aceptó. Esto permite demostrar el anti-replay con dos órdenes:

```powershell
# Mismo número de secuencia que el paquete anterior: el servidor lo trata como repetido.
python -m src.comunicaciones_seguras.tcp_client "Paquete repetido"
```

**Resultado esperado:** `ERROR: paquete de simulacion rechazado`, y en `audit.jsonl` un evento `ipsec_sim` con motivo `ipsec_replay_duplicate`. Para enviar un paquete legítimo nuevo, cambia el número inicial a uno que el servidor no haya visto:

```powershell
$env:IPSEC_SIM_SEQUENCE_START = "100"
python -m src.comunicaciones_seguras.tcp_client "Paquete nuevo"
```

**Resultado esperado:** `RECIBIDO: ...`. Si necesitas empezar de cero, reinicia el servidor (la ventana anti-replay vive en memoria). La misma lógica se comprueba de forma automática, incluidos los paquetes alterados y la ventana de secuencias fuera de orden:

```powershell
python -m unittest discover -s tests -p "test_ipsec_sim.py" -v
```

## 9. Administración remota con SSH (OpenSSH real)

Aquí se usa un servidor OpenSSH real, no una simulación. Se configuran los tres controles que pide el requisito: autenticación por clave pública, restricción de acceso a usuarios autorizados (`AllowUsers`) y registro de intentos (`LogLevel VERBOSE`). Además, el cliente administrativo del proyecto (`ssh_admin.py`) deja cada intento en `audit.jsonl`.

Abre PowerShell **como administrador** para los pasos 9.1 y 9.2, porque modifican el servicio `sshd`.

### 9.1 Instalar y arrancar el servidor OpenSSH

```powershell
Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*"
Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0"
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Get-Service sshd
```

**Resultado esperado:** el servicio `sshd` aparece como `Running`. Si ya estaba instalado, `Add-WindowsCapability` lo indica y puedes continuar.

### 9.2 Restringir usuarios, desactivar contraseñas y activar el registro

Las directivas deben quedar **antes** del bloque `Match Group administrators` que trae el archivo por defecto; si se agregan al final, solo afectarían a ese bloque. Este script crea un respaldo, inserta las líneas en el lugar correcto y reinicia el servicio:

```powershell
$cfg = Join-Path $env:ProgramData "ssh\sshd_config"
Copy-Item $cfg "$cfg.respaldo" -Force
$nuevas = @("PubkeyAuthentication yes", "PasswordAuthentication no", "AllowUsers $env:USERNAME", "LogLevel VERBOSE")
$lineas = @(Get-Content $cfg)
$match = $lineas | Select-String -Pattern '^\s*Match\s' | Select-Object -First 1
if ($match) {
    $i = $match.LineNumber - 1
    $lineas = @($lineas[0..($i - 1)]) + $nuevas + @($lineas[$i..($lineas.Count - 1)])
} else {
    $lineas = $lineas + $nuevas
}
Set-Content -Path $cfg -Value $lineas -Encoding ascii
Restart-Service sshd
& "$env:SystemRoot\System32\OpenSSH\sshd.exe" -T | Select-String "^(allowusers|passwordauthentication|pubkeyauthentication|loglevel) "
```

**Resultado esperado:** la última orden muestra `allowusers` con tu usuario, `passwordauthentication no`, `pubkeyauthentication yes` y `loglevel VERBOSE`. Si falta alguna, revisa el archivo y repite. Para deshacer los cambios, copia `sshd_config.respaldo` sobre `sshd_config` y reinicia el servicio.

### 9.3 Crear la clave autorizada y la clave no autorizada

```powershell
$sshDir = Join-Path $env:USERPROFILE ".ssh"
New-Item -ItemType Directory -Force $sshDir | Out-Null
$key = Join-Path $sshDir "id_ed25519_sdi"
$otra = Join-Path $sshDir "id_ed25519_no_autorizada"
if (-not (Test-Path $key)) { ssh-keygen -t ed25519 -f $key -C "sdi-lab" -N '""' }
if (-not (Test-Path $otra)) { ssh-keygen -t ed25519 -f $otra -C "no-autorizada" -N '""' }
```

Autoriza **solo** la primera clave. Si tu cuenta pertenece al grupo Administradores, OpenSSH para Windows lee `administrators_authorized_keys`, que debe tener permisos restringidos; si no, usa `authorized_keys` en tu perfil:

```powershell
$pub = Get-Content "$key.pub"
$esAdmin = [bool]((whoami /groups) -match "S-1-5-32-544")
if ($esAdmin) {
    $destino = Join-Path $env:ProgramData "ssh\administrators_authorized_keys"
    Add-Content -Path $destino -Value $pub -Encoding ascii
    icacls $destino /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null
} else {
    $destino = Join-Path $sshDir "authorized_keys"
    Add-Content -Path $destino -Value $pub -Encoding ascii
}
"Clave autorizada en: $destino"
```

Registra la identidad del servidor para poder conectar sin desactivar la verificación del host:

```powershell
$known = Join-Path $sshDir "known_hosts_sdi"
ssh-keyscan -t ed25519 localhost | Set-Content -Path $known -Encoding ascii
```

### 9.4 Acceso autorizado y no autorizado

Abre una terminal normal en la carpeta del proyecto. Estas variables las usan tanto el cliente administrativo como las pruebas:

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$sshDir = Join-Path $env:USERPROFILE ".ssh"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
$env:SSH_TEST_HOST = "localhost"
$env:SSH_TEST_USER = $env:USERNAME
$env:SSH_TEST_PRIVATE_KEY_FILE = Join-Path $sshDir "id_ed25519_sdi"
$env:SSH_TEST_KNOWN_HOSTS_FILE = Join-Path $sshDir "known_hosts_sdi"
$env:SSH_TEST_PORT = "22"
python -m src.comunicaciones_seguras.ssh_admin --command whoami
```

**Resultado esperado:** `ACEPTADO: usuario@localhost:22 -> whoami: ...`. Ahora repite el intento con la clave que no está autorizada:

```powershell
$env:SSH_TEST_PRIVATE_KEY_FILE = Join-Path $sshDir "id_ed25519_no_autorizada"
python -m src.comunicaciones_seguras.ssh_admin --command whoami
$env:SSH_TEST_PRIVATE_KEY_FILE = Join-Path $sshDir "id_ed25519_sdi"
```

**Resultado esperado:** `RECHAZADO: ... autenticación por clave rechazada`. La tercera línea restaura la variable.

### 9.5 Ver el registro de intentos

El registro del proyecto muestra quién intentó administrar el equipo y con qué resultado; no contiene rutas ni claves:

```powershell
Get-Content $env:AUDIT_LOG_FILE | Select-String '"operation": "ssh:'
```

El servidor OpenSSH guarda además su propio registro de conexiones en el Visor de eventos (Aplicaciones y servicios > OpenSSH > Operational). Para consultarlo desde PowerShell:

```powershell
Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List
```

**Resultado esperado:** eventos de conexión aceptada para la clave autorizada y de autenticación fallida para la otra.

### 9.6 Pruebas automatizadas de integración

Con las variables del paso anterior definidas, habilita las pruebas reales y añade la clave no autorizada:

```powershell
$env:SSH_TEST_ENABLED = "1"
$env:SSH_TEST_UNAUTHORIZED_KEY_FILE = Join-Path $sshDir "id_ed25519_no_autorizada"
python -m unittest discover -s tests -p "test_ssh.py" -v
```

**Resultado esperado:** las pruebas locales pasan siempre, `test_remote_whoami` confirma el acceso autorizado y `test_unauthorized_key_is_rejected` confirma el rechazo. Para probar también que una cuenta fuera de `AllowUsers` es rechazada, crea una cuenta local sin privilegios y defínela:

```powershell
New-LocalUser -Name "intruso-lab" -Password (Read-Host -AsSecureString "Contraseña para intruso-lab") -Description "Cuenta de prueba SSH"
$env:SSH_TEST_UNAUTHORIZED_USER = "intruso-lab"
python -m unittest discover -s tests -p "test_ssh.py" -v
```

La prueba `test_user_outside_allowed_list_is_rejected` pasa porque `AllowUsers` solo incluye tu usuario. Elimina la cuenta al terminar con `Remove-LocalUser -Name "intruso-lab"`. Si `SSH_TEST_ENABLED` no está definida, las pruebas de integración se omiten y solo corren las locales; una prueba omitida no cuenta como aprobada.

## 10. Cliente y servidor en computadoras diferentes

Las secciones 4 y 5 usan `127.0.0.1`, que siempre apunta al mismo equipo. Para cumplir el requisito de dos computadoras, repite TCP y TLS con dos equipos conectados a la misma red de laboratorio. Los comandos están separados por equipo.

### 10.1 En la computadora servidor

Obtén la IPv4 de la red de laboratorio y comprueba que sea la correcta:

```powershell
$serverIp = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress -notlike "169.254.*" } |
    Select-Object -First 1 -ExpandProperty IPAddress
"IP del servidor: $serverIp"
```

Si el equipo tiene varios adaptadores y la IP mostrada no es la de la red de laboratorio, revisa `ipconfig` y asigna la correcta a `$serverIp`.

El certificado de la sección 3 solo cubre `localhost` y `127.0.0.1`. Genera uno nuevo cuyo SAN incluya la IP del servidor y fírmalo con la misma CA (la clave de la CA se queda en este equipo):

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$openssl = if (Get-Command openssl -ErrorAction SilentlyContinue) { "openssl" } else { "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" }
& $openssl genrsa -out "$pki\server\server-lan.key" 2048
& $openssl req -new -key "$pki\server\server-lan.key" -out "$pki\server\server-lan.csr" -subj "/CN=$serverIp"
@"
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$serverIp
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
"@ | Set-Content -Encoding ascii "$pki\server\server-lan-extensions.cnf"
& $openssl x509 -req -in "$pki\server\server-lan.csr" -CA "$pki\ca\root-ca.crt" -CAkey "$pki\ca\root-ca.key" -CAcreateserial -out "$pki\server\server-lan.crt" -days 365 -sha256 -extfile "$pki\server\server-lan-extensions.cnf"
```

Abre el puerto solo para la red privada y solo desde la computadora cliente (como administrador):

```powershell
$clientIp = Read-Host "IP de la computadora cliente"
New-NetFirewallRule -DisplayName "Lab comunicaciones seguras" -Direction Inbound -Protocol TCP -LocalPort 5000,5001 -Profile Private -RemoteAddress $clientIp -Action Allow
```

Inicia el servidor TCP sin cifrado (Terminal 1):

```powershell
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "0.0.0.0"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_server
```

`0.0.0.0` significa «escuchar en todas las interfaces»; no es la dirección que usa el cliente. Cuando termines la prueba TCP, detén el servidor con `Ctrl+C` y arranca el TLS:

```powershell
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "0.0.0.0"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "$pki\server\server-lan.crt"
$env:TLS_KEY_FILE = "$pki\server\server-lan.key"
python -m src.comunicaciones_seguras.tcp_server
```

### 10.2 En la computadora cliente

Copia desde el servidor **solo** `root-ca.crt` (certificado público de la CA) a una carpeta del cliente, por ejemplo con una memoria USB. Nunca copies `root-ca.key` ni `server-lan.key`. Después, en la carpeta del proyecto del cliente:

```powershell
$serverIp = Read-Host "IP del servidor"
$caFile = Read-Host "Ruta completa de root-ca.crt en esta computadora"
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = $serverIp
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_client "Prueba TCP entre equipos"
```

**Resultado esperado:** `RECIBIDO: Prueba TCP entre equipos`. Esta comunicación **no está cifrada**. Para la versión protegida:

```powershell
$env:COMMUNICATION_MODE = "tls"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = $caFile
$env:TLS_SERVER_NAME = $serverIp
python -m src.comunicaciones_seguras.tcp_client "Prueba TLS entre equipos"
```

**Resultado esperado:** `Conexión TLS validada con <IP>:5001` y `RECIBIDO: Prueba TLS entre equipos`. Para ver el rechazo, apunta `TLS_CA_FILE` a otro certificado de CA (por ejemplo `other-ca.crt` de la sección 3, copiado al cliente) y repite: debe aparecer `CERTIFICATE_VERIFY_FAILED`. No desactives la validación para que desaparezca un error.

### 10.3 Evidencia recomendada de la comparación

Instala Wireshark en uno de los dos equipos, captura en la interfaz de la red de laboratorio y repite las dos pruebas. Con el filtro `tcp.port == 5000` se lee el mensaje en texto claro; con `tcp.port == 5001` solo se ven registros TLS cifrados. Guarda capturas de pantalla de ambos filtros y de las terminales de los dos equipos mostrando su IP (`ipconfig`).

### 10.4 Qué terminal debe permanecer abierta

- **Terminal 1 (servidor):** se mantiene ejecutando `tcp_server`; aquí se ven los mensajes de inicio y los rechazos.
- **Terminal 2 (cliente):** ejecuta `tcp_client` una vez por mensaje.
- **Terminal de pruebas:** cuando no necesites un servidor abierto, ejecuta la suite en la raíz del repositorio. Las variables `TLS_TEST_*` y `SSH_TEST_*` deben definirse en esa misma terminal.

## 11. VPN de acceso remoto y VPN sitio a sitio

El requisito pide **representar** ambas VPN y distinguirlas. El módulo `src/comunicaciones_seguras/vpn_sim.py` lo hace en software: no crea túneles del sistema operativo, pero reproduce lo que diferencia a cada escenario.

| | VPN de acceso remoto | VPN sitio a sitio |
|---|---|---|
| Qué conecta | Un usuario remoto con una red privada | Dos redes completas entre sí |
| Autenticación | Usuario y contraseña de cada persona (scrypt) | Clave precompartida entre gateways |
| Autorización | Por rol, **después** de conectar | Por subredes de origen y destino |
| Dirección interna | IP virtual asignada a la sesión | Los equipos conservan su IP de LAN |
| Protección de paquetes | Sesión autenticada con vigencia | IPsec simulado en modo túnel con anti-replay |

### 11.1 Ejecutar la demostración

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
python -m src.comunicaciones_seguras.vpn_demo
```

La demostración usa tres usuarios temporales en memoria (`admin`, `operador`, `consulta`) con contraseñas de demostración que no se guardan en archivos. Si `AUDIT_LOG_FILE` no está definida, usa un archivo temporal. Muestra, en este orden:

1. **Autenticación:** una contraseña incorrecta se rechaza; el usuario `consulta` se conecta y recibe una IP virtual.
2. **Restricciones posteriores a la conexión:** `consulta` alcanza `intranet-web`, pero `servidor-archivos` y `panel-administracion` se rechazan con `privilegios_insuficientes`. `admin` alcanza todos los recursos, y después de desconectarse su sesión ya no sirve.
3. **Bloqueo por intentos fallidos:** tras tres contraseñas incorrectas, `operador` queda bloqueado temporalmente aunque ahora use la contraseña correcta.
4. **Sitio a sitio:** tráfico válido en ambos sentidos entre `10.10.0.0/24` y `10.20.0.0/24`, con el paquete en modo túnel (encabezado externo e interno).
5. **Ataques al túnel:** reenvío de un paquete capturado (replay), alteración del contenido e inyección desde un gateway con otra clave; los tres se rechazan.
6. **Política de subredes:** tráfico hacia `8.8.8.8` o desde un origen que no pertenece a ningún sitio se rechaza.
7. La comparación de escenarios y el registro de auditoría generado.

### 11.2 Pruebas automatizadas

```powershell
python -m unittest discover -s tests -p "test_vpn_sim.py" -v
```

**Resultado esperado:** todas las pruebas pasan. Cubren credenciales válidas e inválidas, acceso según el rol, expiración y revocación de sesiones, bloqueo, replay, alteración, clave incorrecta, política de subredes, y que el servicio no concede acceso si no puede escribir la auditoría.

### 11.3 VPN real con strongSwan (opcional)

Una VPN real necesita dos gateways con redes propias y no se puede validar con `unittest`. La guía [VPN_IPSEC_REAL_STRONGSWAN.md](VPN_IPSEC_REAL_STRONGSWAN.md) contiene configuraciones de ejemplo para sitio a sitio y para acceso remoto IKEv2. Úsala solo si dispones de ese laboratorio y guarda como evidencia el estado del túnel y los contadores de tráfico.

## 12. Solución de problemas frecuentes

| Síntoma | Comprobación |
|---|---|
| `python` no se reconoce | Reinstala Python con PATH habilitado y reinicia la terminal de VS Code. |
| `Address already in use` | Otra ejecución ocupa el puerto. Detén el proceso anterior o usa otro `TCP_PORT` en ambos extremos. |
| `Connection refused` | Confirma que el servidor sigue ejecutándose y que el cliente usa la misma IP y puerto. |
| Conexión entre equipos agotada | Revisa la IP, que ambos equipos estén en la misma red y la regla de firewall del paso 10.1. |
| Error TLS de CA | Revisa `TLS_CA_FILE` y que sea el certificado público de la CA que firmó el servidor. |
| Error de nombre TLS | `TLS_SERVER_NAME` debe coincidir con un DNS o IP del SAN del certificado (`server-lan.crt` para pruebas entre equipos). |
| Operación protegida denegada por configuración | Configura `AUTH_USERS_FILE` y `AUDIT_LOG_FILE` en el servidor y reinícialo. |
| `ERROR: paquete de simulacion rechazado` en la segunda ejecución del cliente | Es el anti-replay: el número de secuencia ya fue aceptado. Cambia `IPSEC_SIM_SEQUENCE_START` o reinicia el servidor (sección 8). |
| Simulación rechazada desde el primer paquete | Cliente y servidor deben usar la misma clave, SPI y modo; revisa `audit.jsonl`. |
| Prueba TLS omitida | Define las variables `TLS_TEST_*` de la sección 7 en la terminal donde ejecutas `unittest`. |
| Prueba SSH omitida | Es lo esperado mientras `SSH_TEST_ENABLED` no sea `1`. Para habilitarla, completa la sección 9. |
| SSH: `Permission denied` con la clave correcta | Si tu cuenta es de administrador, la clave debe estar en `administrators_authorized_keys` con los permisos del paso 9.3. |
| SSH: `Host key verification failed` | Regenera `known_hosts_sdi` con `ssh-keyscan` (paso 9.3). No desactives la verificación. |

## 13. Cierre seguro

Al terminar, detén cada servidor con `Ctrl+C`. Si abriste reglas de firewall o creaste la cuenta de prueba SSH, elimínalas:

```powershell
Remove-NetFirewallRule -DisplayName "Lab comunicaciones seguras" -ErrorAction SilentlyContinue
```

Antes de publicar cambios revisa qué se va a subir. `git status --short` lista los archivos modificados, `git diff --check` busca errores de formato y `git diff` muestra el contenido. Confirma que no aparezcan claves privadas (`.key`, `.pem`), contraseñas, archivos de usuarios, registros de auditoría ni claves de simulación.

```powershell
git status --short
git diff --check
git diff
```

Esta guía describe un laboratorio académico; no es una certificación de seguridad ni una receta de despliegue en producción.

## 14. Comprobación final de los requisitos

Ejecuta la suite con todas las variables de entorno definidas para que ninguna prueba quede omitida. En una misma terminal:

```powershell
$base = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras"
$pki = Join-Path $base "pki"
$sshDir = Join-Path $env:USERPROFILE ".ssh"
$env:TLS_TEST_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_TEST_CERT_FILE = "$pki\server\server.crt"
$env:TLS_TEST_KEY_FILE = "$pki\server\server.key"
$env:TLS_TEST_SERVER_NAME = "localhost"
$env:TLS_TEST_UNTRUSTED_CA_FILE = "$pki\untrusted-ca\other-ca.crt"
$env:SSH_TEST_ENABLED = "1"
$env:SSH_TEST_HOST = "localhost"
$env:SSH_TEST_USER = $env:USERNAME
$env:SSH_TEST_PRIVATE_KEY_FILE = Join-Path $sshDir "id_ed25519_sdi"
$env:SSH_TEST_KNOWN_HOSTS_FILE = Join-Path $sshDir "known_hosts_sdi"
$env:SSH_TEST_UNAUTHORIZED_KEY_FILE = Join-Path $sshDir "id_ed25519_no_autorizada"
python -m unittest discover -s tests -p "test*.py" -v 2>&1 | Out-File -Encoding utf8 -FilePath ".\resultado_pruebas.txt"
Get-Content ".\resultado_pruebas.txt" -Tail 6
```

`Out-File -Encoding utf8` evita que el archivo quede en UTF-16, que muchos visores no abren bien. El resumen final debe indicar `OK` y ninguna prueba omitida (`skipped`) salvo la de `SSH_TEST_UNAUTHORIZED_USER`, que es opcional. Una prueba omitida no equivale a una prueba aprobada.

La tabla relaciona cada requisito con la comprobación y el resultado que lo confirma. Marca cada fila solo después de obtener el resultado.

| Requisito | Qué ejecutar | Resultado que lo confirma |
|---|---|---|
| 1. Cliente y servidor, TCP frente a TLS, en computadoras diferentes | Secciones 4, 5 y 10 | TCP responde `RECIBIDO:` y se lee en claro en la captura; TLS responde y la captura solo muestra registros cifrados. |
| 2. TLS y validación de certificados | Sección 5 y pruebas `test_tls.py` | Conexión válida; nombre incorrecto y CA no confiable rechazados. |
| 3. PKI y cadena de confianza | Sección 3 y pruebas TLS | El certificado del servidor lo firma la CA de laboratorio y el cliente solo confía en esa CA. |
| 4. SSH: autenticación, restricción y registro | Sección 9 y `test_ssh.py` | Acceso autorizado aceptado; clave y usuario no autorizados rechazados; intentos en `audit.jsonl` y en el registro de OpenSSH. |
| 5. IPsec: transporte, túnel y replay | Sección 8 y `test_ipsec_sim.py` | Ambos modos funcionan; el paquete repetido y el alterado se rechazan y se auditan. |
| 6. VPN de acceso remoto | Sección 11 (`vpn_demo` y `test_vpn_sim.py`) | Usuario autenticado, IP virtual, acceso limitado por rol, sesión revocable. |
| 7. VPN sitio a sitio | Sección 11 (`vpn_demo` y `test_vpn_sim.py`) | Tráfico entre dos subredes en modo túnel, sin usuarios, con política por subred. |
| 8. Autenticación, autorización y registro | Sección 6 y `test_auth.py` | Contraseña inválida rechazada; operación sin permiso rechazada; eventos permitidos y denegados en `audit.jsonl`, sin contraseñas. |
| 9. Pruebas de seguridad | Suite completa | Resumen con `OK` y sin pruebas omitidas inesperadas. |
| 10. Documentación | `README.md` y esta guía | Arquitectura, ejecución, función de cada mecanismo, diferencias y limitaciones. |

Las pruebas de TCP, TLS, usuarios, permisos, IPsec simulado y VPN simuladas se ejecutan en una sola computadora. SSH necesita el servidor OpenSSH de la sección 9 y la comprobación entre dos computadoras necesita ambos equipos. Una VPN real con strongSwan es opcional y requiere sus propios gateways.
