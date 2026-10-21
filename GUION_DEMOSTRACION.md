# Guion de demostración (una sola laptop)

Comandos para exponer el proyecto en una sola computadora, con las rutas ya escritas. Se pega cada bloque directo en la terminal indicada, sin agregar archivos por fuera.

- **Terminal 1** es el servidor y se queda abierta. **Terminal 2** es el cliente.
- Cada bloque empieza con `Set-Location` hacia la carpeta del proyecto. No lo quites.
- Las variables `$env:...` valen solo en la terminal donde se pegan. Si abres una terminal nueva, vuelve a pegar su bloque.
- Antes de arrancar un servidor nuevo, detén el anterior con `Ctrl+C`.
- **No copies la salida de error como si fuera un comando**: líneas como `usage: tcp_client.py`, `[-h]` o `invalid choice` son mensajes informativos, no se ejecutan.
- La contraseña se escribe únicamente cuando aparece `Contraseña:`; nunca la pegues al final de `--operation admin_info`.

| Paso | Qué se muestra | Requisito |
|---|---|---|
| 0 | Revisión previa de archivos | — |
| 1 | Mensaje con TLS | 1 |
| 2 | El cliente rechaza certificados no confiables | 2, 3 |
| 3 | Usuarios, permisos por rol y bitácora | 8 |
| 4 | IPsec simulado: transporte, túnel y replay | 5 |
| 5 | SSH autorizado y no autorizado, con registro | 4 |
| 6 | VPN de acceso remoto y sitio a sitio | 6, 7 |
| 7 | Pruebas automáticas | 9 |

> El requisito 1 pide cliente y servidor en computadoras diferentes. En esta laptop ambos corren en el mismo equipo (`127.0.0.1`).

## Paso 0. Revisión previa (una terminal)

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$archivos = @(
    "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\ca\root-ca.crt",
    "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\server\server.crt",
    "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\server\server.key",
    "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\untrusted-ca\other-ca.crt",
    "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\users.json",
    "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\ipsec\ipsec_sim_key.json",
    "$env:USERPROFILE\.ssh\id_ed25519_sdi",
    "$env:USERPROFILE\.ssh\id_ed25519_no_autorizada"
)
foreach ($a in $archivos) { if (Test-Path $a) { "OK     $a" } else { "FALTA  $a" } }
Get-Service sshd | Select-Object Name, Status
```

**Esperado:** ocho `OK` y `sshd` en `Running` (este último solo lo usa el paso 5).

## Pasos 1 y 2. TLS y certificados no confiables

**Por qué:** TLS cifra la sesión y el cliente solo confía en servidores cuyo certificado firmó su CA y cuyo nombre coincide. Si falla cualquiera de las dos cosas, la conexión se corta antes de enviar datos.

**Terminal 1 (servidor TLS):**

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\server\server.crt"
$env:TLS_KEY_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\server\server.key"
$env:AUTH_USERS_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\users.json"
$env:AUDIT_LOG_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\audit.jsonl"
python -m src.comunicaciones_seguras.tcp_server
```

**Esperado:** `Servidor TLS escuchando en 127.0.0.1:5001`. Los dos `WARNING` sobre `AUTH_USERS_FILE` y `AUDIT_LOG_FILE` son normales en este paso.

**Terminal 2 (cliente):**

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\ca\root-ca.crt"
$env:TLS_SERVER_NAME = "localhost"
python -m src.comunicaciones_seguras.tcp_client "Mensaje con TLS"
```

**Esperado:** `Conexión TLS validada con 127.0.0.1:5001` y `RECIBIDO: Mensaje con TLS`.

Rechazo por CA equivocada:

```powershell
$env:TLS_CA_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\untrusted-ca\other-ca.crt"
python -m src.comunicaciones_seguras.tcp_client "Esto no debe llegar"
$env:TLS_CA_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\ca\root-ca.crt"
```

Rechazo por nombre equivocado:

```powershell
$env:TLS_SERVER_NAME = "servidor-falso.local"
python -m src.comunicaciones_seguras.tcp_client "Esto tampoco debe llegar"
$env:TLS_SERVER_NAME = "localhost"
```

**Esperado:** `CERTIFICATE_VERIFY_FAILED` en ambos casos (`unable to get local issuer certificate` en el primero, `Hostname mismatch` en el segundo), sin `RECIBIDO`. La última línea de cada bloque restaura el valor correcto. Si en el segundo caso el servidor de la Terminal 1 se apaga (`WinError 10054`), vuelve a pegar su bloque y continúa.

## Paso 3. Usuarios, roles y bitácora

**Por qué:** autenticar es saber quién eres; autorizar es decidir qué puedes hacer. La respuesta al cliente es genérica (`acceso_denegado`) para no ayudar a un atacante, pero la bitácora guarda el motivo real.

Detén el servidor con `Ctrl+C` y pega esto.

**Terminal 1 (servidor):**

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$env:AUTH_USERS_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\users.json"
$env:AUDIT_LOG_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\audit.jsonl"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\server\server.crt"
$env:TLS_KEY_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\server\server.key"
python -m src.comunicaciones_seguras.tcp_server
```

**Terminal 2 (cliente):** pega el bloque del cliente de los pasos 1 y 2 (el de `Mensaje con TLS`, sin las líneas de restauración) y luego ejecuta, uno por uno:

```powershell
python -m src.comunicaciones_seguras.tcp_client --username admin --operation admin_info
python -m src.comunicaciones_seguras.tcp_client --username consulta --operation status
python -m src.comunicaciones_seguras.tcp_client --username consulta --operation list_resources
python -m src.comunicaciones_seguras.tcp_client --username admin --operation status
```

Escribe la contraseña real en los tres primeros. En el cuarto, escribe una incorrecta a propósito.

| Comando | Esperado |
|---|---|
| `admin` + `admin_info` | `"result": "ok"` |
| `consulta` + `status` | `"result": "ok"` |
| `consulta` + `list_resources` | `"result": "denied"`, `"reason": "acceso_denegado"` (se autentica, pero no tiene permiso) |
| `admin` con contraseña mala | `"result": "denied"`, `"reason": "acceso_denegado"` (no se autentica) |

```powershell
Get-Content "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\audit.jsonl" -Tail 5
```

**Esperado:** una línea por intento con `allowed` o `denied`; los motivos reales son `permiso_insuficiente` y `credenciales_invalidas`. Ninguna contraseña aparece en el archivo.

## Paso 4. IPsec simulado y replay

**Por qué:** cada paquete lleva un número de secuencia y un sello de autenticidad. Si un atacante graba un paquete válido y lo reenvía, el receptor lo rechaza porque ese número ya se usó. El modo transporte protege el mensaje entre dos extremos; el modo túnel mete el paquete original dentro de otro, como al conectar dos redes. El sello garantiza integridad y autenticidad, pero este simulador no cifra el contenido.

Detén el servidor con `Ctrl+C`.

**Terminal 1 (servidor):**

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$env:IPSEC_SIM_ENABLED = "1"
$env:IPSEC_SIM_KEY_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\ipsec\ipsec_sim_key.json"
$env:IPSEC_SIM_SPI = "LAB-01"
$env:IPSEC_SIM_MODE = "transport"
$env:AUTH_USERS_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\users.json"
$env:AUDIT_LOG_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\audit.jsonl"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\server\server.crt"
$env:TLS_KEY_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\server\server.key"
python -m src.comunicaciones_seguras.tcp_server
```

**Terminal 2 (cliente):**

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$env:IPSEC_SIM_ENABLED = "1"
$env:IPSEC_SIM_KEY_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\ipsec\ipsec_sim_key.json"
$env:IPSEC_SIM_SPI = "LAB-01"
$env:IPSEC_SIM_MODE = "transport"
$env:IPSEC_SIM_SEQUENCE_START = "1"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\ca\root-ca.crt"
$env:TLS_SERVER_NAME = "localhost"
python -m src.comunicaciones_seguras.tcp_client "Paquete 1 en modo transporte"
```

**Esperado:** `RECIBIDO: ...`

Replay (mismo número de secuencia):

```powershell
python -m src.comunicaciones_seguras.tcp_client "Paquete repetido"
Get-Content "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\audit.jsonl" -Tail 2
```

**Esperado:** `ERROR: paquete de simulacion rechazado`, y en la bitácora un evento `ipsec_sim` con motivo `ipsec_replay_duplicate`.

Paquete nuevo legítimo:

```powershell
$env:IPSEC_SIM_SEQUENCE_START = "100"
python -m src.comunicaciones_seguras.tcp_client "Paquete nuevo"
```

**Esperado:** `RECIBIDO: ...`

Modo túnel: en la Terminal 1, `Ctrl+C` y:

```powershell
$env:IPSEC_SIM_MODE = "tunnel"
python -m src.comunicaciones_seguras.tcp_server
```

En la Terminal 2:

```powershell
$env:IPSEC_SIM_MODE = "tunnel"
$env:IPSEC_SIM_SEQUENCE_START = "1"
python -m src.comunicaciones_seguras.tcp_client "Paquete 1 en modo tunel"
```

**Esperado:** `RECIBIDO: ...` Reiniciar el servidor borra su memoria de secuencias, por eso vuelve a aceptar el número 1.

## Paso 5. SSH autorizado y no autorizado (terminal nueva)

**Por qué:** SSH autentica con clave pública, restringe el acceso a los usuarios autorizados y registra cada intento. Una clave privada no se puede adivinar como una contraseña. Requiere `sshd` en `Running` (paso 0).

Primero, una sola vez, registra la identidad del servidor SSH. Se guarda en el archivo `known_hosts` que Windows ya usa, así que no creas nada nuevo:

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519_sdi" -o StrictHostKeyChecking=accept-new localhost whoami
```

**Esperado:** muestra tu usuario de Windows (`equipo\brand`). Si pide contraseña, la clave `id_ed25519_sdi` no está autorizada en el servidor SSH: avísame.

Ahora la demostración:

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$env:AUDIT_LOG_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\audit.jsonl"
$env:SSH_TEST_HOST = "localhost"
$env:SSH_TEST_USER = $env:USERNAME
$env:SSH_TEST_PORT = "22"
$env:SSH_TEST_PRIVATE_KEY_FILE = "$env:USERPROFILE\.ssh\id_ed25519_sdi"
python -m src.comunicaciones_seguras.ssh_admin --command whoami
```

**Esperado:** `ACEPTADO: ... -> whoami: ...`

```powershell
$env:SSH_TEST_PRIVATE_KEY_FILE = "$env:USERPROFILE\.ssh\id_ed25519_no_autorizada"
python -m src.comunicaciones_seguras.ssh_admin --command whoami
$env:SSH_TEST_PRIVATE_KEY_FILE = "$env:USERPROFILE\.ssh\id_ed25519_sdi"
```

**Esperado:** `RECHAZADO: ... autenticación por clave rechazada`. La última línea restaura la clave buena.

```powershell
Get-Content "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\audit.jsonl" | Select-String '"operation": "ssh:'
```

**Esperado:** un evento `allowed` y otro `denied`.

## Paso 6. VPN de acceso remoto y sitio a sitio

**Por qué:** la VPN de acceso remoto protege a una persona que entra a una red privada, y por eso importan el usuario y el rol. La VPN sitio a sitio protege el tráfico entre dos redes completas, y por eso importan las subredes y la clave compartida entre gateways. Ambas están simuladas, como pide el enunciado.

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
python -m src.comunicaciones_seguras.vpn_demo
```

**Esperado:** líneas `ACEPTADO` y `RECHAZADO` con sus motivos. Señala tres cosas:

- `consulta` entra a `intranet-web`, pero `panel-administracion` sale `privilegios_insuficientes`.
- `operador` queda bloqueado tras 3 contraseñas malas, aunque luego use la correcta.
- En sitio a sitio, `REPLAY`, `MODIFICACIÓN` e `INYECCIÓN` salen `RECHAZADO`.

## Paso 7. Pruebas automáticas

**Por qué:** demuestra que lo mostrado a mano también se verifica de forma automática y repetible.

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
$env:TLS_TEST_CA_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\ca\root-ca.crt"
$env:TLS_TEST_CERT_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\server\server.crt"
$env:TLS_TEST_KEY_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\server\server.key"
$env:TLS_TEST_SERVER_NAME = "localhost"
$env:TLS_TEST_UNTRUSTED_CA_FILE = "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\pki\untrusted-ca\other-ca.crt"
$env:SSH_TEST_ENABLED = "1"
$env:SSH_TEST_HOST = "localhost"
$env:SSH_TEST_USER = $env:USERNAME
$env:SSH_TEST_PORT = "22"
$env:SSH_TEST_PRIVATE_KEY_FILE = "$env:USERPROFILE\.ssh\id_ed25519_sdi"
$env:SSH_TEST_UNAUTHORIZED_KEY_FILE = "$env:USERPROFILE\.ssh\id_ed25519_no_autorizada"
python -m unittest discover -s tests -p "test*.py" -v 2>&1 | Out-File -Encoding utf8 -FilePath ".\resultado_pruebas.txt"
Get-Content ".\resultado_pruebas.txt" -Tail 6
```

**Esperado:** `OK` al final. Es normal que queden una o dos pruebas omitidas (`skipped`): la de enlaces simbólicos, que Windows no permite sin permisos especiales, y la de un usuario fuera de `AllowUsers`, que es opcional. Una prueba omitida no cuenta como aprobada.


## Si olvidaste la contraseña de un usuario

**No ejecutes** `python -m src.comunicaciones_seguras.user_setup --overwrite`: reemplaza el almacén completo y puede cambiar las tres cuentas. El repositorio ahora incluye una utilidad que cambia una sola cuenta y crea un respaldo.

En una terminal PowerShell:

```powershell
$project = Join-Path $env:USERPROFILE "OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
Set-Location $project
$base = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras"
$env:AUTH_USERS_FILE = Join-Path $base "auth\users.json"
python -m src.comunicaciones_seguras.user_password_reset --username admin
```

Escribe la nueva contraseña y confírmala cuando se solicite; los caracteres no se mostrarán. Para otra cuenta, cambia `admin` por `operador` o `consulta`.

Después, detén el servidor con `Ctrl+C` en Terminal 1 y vuelve a pegar el bloque de inicio del servidor del paso correspondiente. Luego ejecuta de nuevo la prueba del cliente desde Terminal 2.

## Antes de ejecutar cualquier comando

- Ejecuta los bloques en el orden indicado y en la terminal que se menciona.
- Mantén abierta Terminal 1 mientras haces pruebas desde Terminal 2.
- Si cambias una variable `$env:...`, recuerda que solo afecta esa terminal.
- Una prueba de rechazo de certificado debe fallar; restaura los valores válidos al terminar.
- No compartas `users.json`, claves privadas, hashes ni contraseñas.

## Frases para cerrar la exposición

- «TLS, la PKI y SSH son reales; IPsec y las VPN son simulaciones, porque el propósito es mostrar su funcionamiento y sus diferencias.»
- «TLS y SSH protegen una sesión entre dos puntos. IPsec y la VPN sitio a sitio protegen tráfico entre redes. La VPN de acceso remoto controla quién entra a una red privada.»
- «Autenticar es saber quién eres; autorizar es decidir qué puedes hacer.»
- «Todo queda registrado: accesos permitidos, rechazados y operaciones administrativas.»
- «Es un laboratorio: no está pensado para producción. Las limitaciones están documentadas en el README.»