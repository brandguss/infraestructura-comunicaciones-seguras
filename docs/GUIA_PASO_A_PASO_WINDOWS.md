# Guía paso a paso para Windows y PowerShell

Esta guía te lleva desde la preparación de Windows hasta la comprobación de cada parte del proyecto. Primero se prueban las comunicaciones en una sola computadora; después se preparan los certificados, los usuarios, la auditoría, la simulación IPsec y la integración SSH. Cada bloque explica para qué sirve, qué debe pasar en pantalla y cómo interpretar un error. Los archivos que contienen claves y datos de usuarios se guardan fuera del repositorio para evitar que terminen publicados en GitHub.

## 1. Abrir el proyecto y comprobar Python

Abre dos terminales de PowerShell en VS Code. La primera se usará normalmente para mantener el servidor en ejecución y la segunda para lanzar el cliente o las pruebas. El comando `Set-Location` coloca la terminal dentro del proyecto, mientras que `python --version` confirma que Windows encuentra Python y `git status --short` permite ver si hay cambios locales pendientes.

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
python --version
git status --short
```

Se requiere Python 3.13 o una versión compatible. Si `python` no se reconoce, instala Python desde python.org y marca **Add Python to PATH**; después cierra y vuelve a abrir VS Code. El comando `git status --short` debe mostrar los cambios locales, si existen.

No necesitas instalar paquetes externos de Python para ejecutar las pruebas actuales, porque se utiliza la biblioteca estándar. El siguiente comando busca los archivos de prueba dentro de `tests` y ejecuta cada caso encontrado. Sirve como primera comprobación: si falla aquí, conviene resolver ese error antes de iniciar servidores o configurar la red.

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

## 8. Configurar y probar la simulación educativa tipo IPsec

Este componente sirve para estudiar conceptos relacionados con IPsec desde el programa Python: identifica paquetes, calcula un HMAC para detectar cambios y permite probar el rechazo de mensajes repetidos. No cifra la carga ni crea una interfaz de red del sistema operativo, por lo que sus resultados comprueban la simulación y no un túnel VPN real. Para generar la clave se utiliza una ruta fuera del repositorio y se configura el mismo archivo en cliente y servidor.

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

Esta prueba comprueba una conexión SSH real mediante OpenSSH, no una simulación en Python. Para que funcione, el servidor debe estar activo, la cuenta de destino debe autorizar la clave pública y el cliente debe reconocer la clave de identidad del servidor. El hecho de que el servicio `sshd` esté encendido solo confirma que escucha; no demuestra que la autenticación por clave ya esté configurada.

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
python -m unittest discover -s tests -p "test_ssh.py" -v
```

Si no se ha preparado la clave, el usuario remoto o la confianza del host, deja la prueba deshabilitada; la suite de pruebas unitarias de configuración seguirá siendo ejecutable. No es seguro desactivar la comprobación de identidad del servidor solo para que pase el test.

## 10. Ejecución desde dos computadoras de la misma red

Cuando las pruebas locales funcionan, puedes repetirlas entre dos computadoras conectadas a una red privada. `127.0.0.1` siempre apunta al propio equipo, por lo que en una prueba entre computadoras debe usarse la IP del servidor. El servidor debe escuchar en una interfaz accesible y el firewall debe permitir únicamente el tráfico necesario desde la red de laboratorio.

1. En la computadora servidor, elige una IP privada fija o reservada en el router.
2. Configura `TCP_HOST=0.0.0.0` en el servidor para escuchar en interfaces IPv4 locales y conserva el puerto `5001` para TLS.
3. En el firewall de Windows, permite el puerto TCP solo en el perfil/red privada y desde la IP cliente esperada. No desactives el firewall.
4. El cliente configura `TCP_HOST` con la IP real del servidor y `TLS_SERVER_NAME` con un nombre que figure en el SAN del certificado. Si se conecta por IP, el certificado debe incluir esa IP como SAN.
5. Copia al cliente solo el certificado público de la CA (`root-ca.crt`), nunca la clave privada de la CA ni la clave privada del servidor.
6. Ejecuta primero la prueba TLS normal; luego la prueba con CA no confiable. Documenta el resultado y la IP/puerto utilizados.

No expongas el puerto a Internet ni uses la CA de laboratorio para sistemas reales.

## 11. VPN de acceso remoto y VPN sitio a sitio: diferencia importante

La simulación del paso anterior y una VPN real son comprobaciones diferentes. Para una VPN de acceso remoto, un usuario conecta su equipo al gateway y recibe acceso a las redes autorizadas. En una VPN sitio a sitio, dos gateways protegen el tráfico entre dos redes. La guía de strongSwan contiene configuraciones de ejemplo, pero para demostrar el túnel se deben adaptar las direcciones y secretos al laboratorio, levantar ambos extremos y confirmar que el tráfico pasa por la conexión IPsec.

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

Al terminar, detén cada servidor con `Ctrl+C`. Los siguientes comandos permiten revisar los cambios antes de publicarlos: `git status --short` lista los archivos modificados, `git diff --check` busca problemas de espacios y formato, y `git diff` muestra el contenido que se va a incluir. Antes de hacer commit, confirma que no aparezcan claves privadas, contraseñas, archivos de usuarios ni registros de auditoría.

```powershell
git status --short
git diff --check
git diff
```

Antes de hacer commit, revisa que no haya archivos `.key`, `.pem`, usuarios, auditorías ni claves de simulación dentro del repositorio. Esta guía describe un laboratorio académico; no es una certificación de seguridad ni una receta de despliegue en producción.


## 15. Comprobación final de los requisitos

Cuando hayas terminado las secciones anteriores, ejecuta las comprobaciones en este orden. La idea es confirmar cada función por separado y conservar una evidencia clara, en vez de asumir que todo funciona porque el servidor inició sin errores.

Primero ejecuta las pruebas unitarias de TCP, autenticación, autorización y simulación IPsec. El comando debe terminar con `OK`; cualquier `FAIL` o `ERROR` significa que hay que revisar el caso que aparece unas líneas antes del resumen. Una prueba marcada como `skipped` no se ejecutó y debe explicarse en la entrega.

```powershell
python -m unittest discover -s tests -p "test*.py" -v
```

Después, en la misma terminal, define las rutas de los certificados que generaste y ejecuta nuevamente la suite. Esta segunda ejecución permite comprobar los casos TLS que dependen de archivos externos, incluido el rechazo de una CA no confiable.

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:TLS_TEST_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_TEST_CERT_FILE = "$pki\server\server.crt"
$env:TLS_TEST_KEY_FILE = "$pki\server\server.key"
$env:TLS_TEST_SERVER_NAME = "localhost"
$env:TLS_TEST_UNTRUSTED_CA_FILE = "$pki\untrusted-ca\other-ca.crt"
python -m unittest discover -s tests -p "test*.py" -v
```

En la salida, confirma que no haya fallos y que la prueba de certificado no confiable ya no aparezca como omitida. Si una prueba TLS falla, comprueba las rutas, la vigencia del certificado y que el certificado incluya el nombre utilizado por el cliente.

La siguiente tabla sirve para relacionar cada requisito con una prueba observable. Marca cada fila únicamente después de haber obtenido el resultado indicado.

| Requisito | Prueba que debes ejecutar | Resultado que confirma la función |
|---|---|---|
| Comunicación TCP | Sección 4, cliente y servidor en terminales separadas | El cliente recibe la respuesta `RECIBIDO:`. |
| Comunicación cifrada TLS | Sección 5, usando la CA de laboratorio | El cliente valida el certificado y recibe la respuesta. |
| Validación de identidad del servidor | Pruebas TLS con `TLS_TEST_SERVER_NAME=localhost` | La conexión con el nombre correcto funciona; la prueba de nombre incorrecto es rechazada. |
| Rechazo de una CA no confiable | Pruebas TLS con `TLS_TEST_UNTRUSTED_CA_FILE` | El caso de certificado no confiable se ejecuta y pasa al comprobar el rechazo. |
| Autenticación | Sección 6 y prueba con una cuenta existente | Una contraseña válida permite autenticarse; una inválida no debe autorizar la operación. |
| Autorización por rol | Sección 6, primero `admin_info` como `admin`, luego `list_resources` como `consulta` | La operación permitida se acepta y la operación sin permisos se rechaza. |
| Auditoría | Inspecciona `$auth\audit.jsonl` después de las dos operaciones | Se guardan eventos relevantes y no aparecen contraseñas. |
| Simulación IPsec | Sección 8 y pruebas `test_ipsec_sim.py` | Pasan las pruebas de integridad, modo configurado y anti-replay que define el módulo. Esto no prueba una VPN real. |
| Integración SSH | Sección 9, solo después de autorizar la clave pública y confiar en el host | La prueba de integración termina correctamente sin desactivar la validación de la identidad del servidor. |
| VPN sitio a sitio | Guía `VPN_IPSEC_REAL_STRONGSWAN.md`, dos gateways y hosts en ambas LAN | El túnel se establece, aumentan los contadores de tráfico y los hosts de ambas subredes se comunican. |
| VPN de acceso remoto | Guía `VPN_IPSEC_REAL_STRONGSWAN.md`, cliente y gateway configurados | El usuario se autentica, recibe una IP del pool y llega solo a los recursos autorizados. |

Las pruebas de TCP, TLS, usuarios, permisos y simulación se pueden ejecutar en la misma computadora. SSH necesita una cuenta y una clave autorizadas. Las VPN necesitan máquinas o gateways con redes reales; no es posible demostrar esos dos requisitos con solo ejecutar `unittest` en una computadora. Si no tienes dos gateways, deja documentado que la guía de configuración está preparada pero el túnel no se ha validado físicamente, en lugar de presentar una prueba de simulación como si fuera una conexión VPN.

Para guardar un resumen de la suite en un archivo de evidencia, puedes ejecutar:

```powershell
python -m unittest discover -s tests -p "test*.py" -v 2>&1 | Tee-Object -FilePath ".\resultado_pruebas.txt"
```

El archivo `resultado_pruebas.txt` contiene la salida de la ejecución y se puede revisar junto con las capturas de las terminales. Antes de publicarlo, comprueba que no incluya rutas privadas que no quieras compartir ni datos sensibles.


## 16. Cómo usar las terminales y probar desde dos computadoras

Las primeras pruebas de las secciones 4 y 5 usan `127.0.0.1`. Esto es útil para comprobar que el programa arranca y que cliente y servidor se entienden, pero ambos procesos están en la misma computadora. Para demostrar el requisito de la práctica, repite TCP y TLS con dos equipos diferentes conectados a la misma red de laboratorio.

### Preparación de la computadora servidor

En el equipo que ejecutará el servidor, abre PowerShell y consulta la dirección IPv4:

```powershell
ipconfig
```

Identifica la dirección IPv4 del adaptador conectado a la red de laboratorio; por ejemplo, en los siguientes comandos se usa `192.168.1.50` como ejemplo. Sustitúyela por la dirección real del servidor. No copies esa dirección de ejemplo sin comprobarla.

En la **Terminal 1 del servidor**, entra en la carpeta del proyecto y configura el servidor para escuchar en las interfaces de red:

```powershell
Set-Location "RUTA\infraestructura-comunicaciones-seguras"
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "0.0.0.0"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_server
```

`0.0.0.0` indica al servidor que escuche en las interfaces IPv4 disponibles; no es la dirección que debe usar el cliente. Mantén abierta esta terminal mientras haces la prueba.

En el firewall de Windows crea una regla de entrada para el puerto TCP que vas a probar y limita el origen a la red privada del laboratorio. No abras el puerto a redes públicas. Si el cliente no logra conectar, comprueba primero que ambos equipos estén en la misma red, que la dirección IPv4 sea correcta y que el firewall permita la conexión.

### Prueba TCP desde la computadora cliente

En la computadora cliente, abre PowerShell y entra en la carpeta del repositorio. En la **Terminal 2 del cliente**, utiliza la IP real del servidor:

```powershell
Set-Location "RUTA\infraestructura-comunicaciones-seguras"
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "192.168.1.50"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_client "Prueba TCP entre equipos"
```

Cambia `192.168.1.50` por la dirección real del servidor. El resultado esperado es una respuesta que empieza por `RECIBIDO:`. Esto confirma la comunicación entre computadoras; el contenido de esta prueba TCP no está cifrado. Cuando termines, detén el servidor con `Ctrl+C`.

### Prueba TLS entre computadoras

Para TLS no basta con cambiar la IP del cliente: el certificado del servidor tiene que identificar el nombre que utiliza el cliente. El certificado generado en la sección 3 solo incluye `localhost` y `127.0.0.1`, por lo que no validará la dirección IP de otro equipo. Genera un certificado de servidor cuyo SAN contenga la IP real o el nombre DNS de la computadora servidor y fírmalo con la CA de laboratorio. Conserva la clave privada fuera del repositorio.

En la computadora servidor, usa el certificado nuevo y su clave privada:

```powershell
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "0.0.0.0"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "RUTA\server.crt"
$env:TLS_KEY_FILE = "RUTA\server.key"
python -m src.comunicaciones_seguras.tcp_server
```

En la computadora cliente, copia de forma segura el certificado público de la CA, no la clave privada de la CA. Configura la IP de conexión y el nombre que aparece en el SAN del certificado:

```powershell
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "192.168.1.50"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = "RUTA\root-ca.crt"
$env:TLS_SERVER_NAME = "192.168.1.50"
python -m src.comunicaciones_seguras.tcp_client "Prueba TLS entre equipos"
```

Los valores de ruta son marcadores y deben reemplazarse por las rutas existentes en cada computadora. Si el SAN contiene un nombre DNS en lugar de la IP, configura `TLS_SERVER_NAME` con ese nombre y asegúrate de que el cliente pueda resolverlo. La prueba correcta debe mostrar que TLS validó el certificado y que se recibió la respuesta. Si la validación falla, revisa la CA, el SAN, las fechas del certificado y el nombre configurado; no desactives la validación para evitar el error.

### Qué terminal debe permanecer abierta

- **Terminal 1 (servidor):** permanece ejecutando `tcp_server`; aquí se observan mensajes de inicio y errores del servidor.
- **Terminal 2 (cliente):** ejecuta `tcp_client` una vez por cada mensaje de prueba y muestra el resultado de la conexión.
- **Terminal de pruebas:** cuando no necesites mantener un servidor abierto, ejecuta `python -m unittest discover -s tests -p "test*.py" -v` en la raíz del repositorio. Las variables de entorno de TLS deben definirse en esa misma terminal antes de lanzar las pruebas.

No compartas claves privadas ni copies `server.key` o `root-ca.key` a la computadora cliente. El cliente solo necesita el certificado público de la CA para validar al servidor.
