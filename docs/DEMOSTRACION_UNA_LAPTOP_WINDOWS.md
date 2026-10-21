# Demostración en una sola laptop (Windows / PowerShell)

Esta guía es la ruta rápida para ejecutar el cliente y el servidor en la misma computadora y comprobar TLS, autenticación, roles y auditoría. Para la exposición completa de IPsec, SSH y VPN, continúa con [la guía paso a paso](GUIA_PASO_A_PASO_WINDOWS.md).

> **Importante:** los bloques de código son comandos. No copies las líneas que aparecen como salida, por ejemplo `usage: tcp_client.py`, `[-h]` o `Falta el nombre de tipo`. Esos textos son mensajes de ayuda o errores, no comandos.

## 1. Antes de comenzar

- Abre dos terminales PowerShell en VS Code.
- **Terminal 1** será el servidor y permanecerá abierta.
- **Terminal 2** será el cliente.
- Ejecuta cada bloque completo en la terminal indicada. Las variables `$env:...` no se comparten entre terminales.
- No arranques otro servidor si ya hay uno activo. Para detenerlo, usa `Ctrl+C` en Terminal 1.
- Los certificados y usuarios deben existir en la carpeta externa `%USERPROFILE%\.infraestructura-comunicaciones-seguras`.

### Ruta del proyecto

La ruta que se usó en esta demostración es:

```powershell
$project = "C:\Users\brand\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
Set-Location $project
Test-Path ".\src\comunicaciones_seguras\tcp_client.py"
```

El último comando debe devolver `True`. Si devuelve `False`, corrige únicamente la variable `$project` para que apunte a la carpeta real del repositorio; no ejecutes los comandos desde otra carpeta.

### Comprobar archivos necesarios

Ejecuta en cualquiera de las terminales:

```powershell
$base = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras"
$archivos = @(
    "$base\pki\ca\root-ca.crt",
    "$base\pki\server\server.crt",
    "$base\pki\server\server.key",
    "$base\pki\untrusted-ca\other-ca.crt",
    "$base\auth\users.json"
)
foreach ($archivo in $archivos) {
    if (Test-Path $archivo) { "OK     $archivo" }
    else { "FALTA  $archivo" }
}
```

Si falta un certificado, revisa las secciones 2 y 3 de la [guía completa](GUIA_PASO_A_PASO_WINDOWS.md). Si falta `users.json`, sigue la sección “Si olvidaste la contraseña” al final de este documento. **No ejecutes `user_setup --overwrite`** para intentar recuperar una cuenta: reemplaza el almacén completo de usuarios.

## 2. Terminal 1: iniciar el servidor TLS

Pega este bloque completo en **Terminal 1**. Déjala abierta:

```powershell
$project = "C:\Users\brand\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
Set-Location $project
$base = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "$base\pki\server\server.crt"
$env:TLS_KEY_FILE = "$base\pki\server\server.key"
$env:AUTH_USERS_FILE = "$base\auth\users.json"
$env:AUDIT_LOG_FILE = "$base\auth\audit.jsonl"
python -m src.comunicaciones_seguras.tcp_server
```

**Resultado esperado:** el servidor indica que escucha en `127.0.0.1:5001`. Si aparece que el puerto ya está en uso, detén el servidor anterior con `Ctrl+C` en la terminal donde se ejecuta. No cambies el puerto solo en una terminal: cliente y servidor deben usar el mismo.

## 3. Terminal 2: configurar el cliente TLS

Pega este bloque completo en **Terminal 2**. Es necesario repetir las variables en esta terminal:

```powershell
$project = "C:\Users\brand\OneDrive\Documentos\SDI\infraestructura-comunicaciones-seguras"
Set-Location $project
$base = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = "$base\pki\ca\root-ca.crt"
$env:TLS_SERVER_NAME = "localhost"
$env:AUTH_USERS_FILE = "$base\auth\users.json"
$env:AUDIT_LOG_FILE = "$base\auth\audit.jsonl"
```

## 4. Probar un mensaje TLS

En Terminal 2:

```powershell
python -m src.comunicaciones_seguras.tcp_client "Mensaje con TLS"
```

Debe aparecer `Conexión TLS validada con 127.0.0.1:5001` y una respuesta `RECIBIDO: ...`. Esto demuestra que el cliente validó el certificado y recibió respuesta del servidor.

## 5. Probar autenticación y permisos

Ejecuta estos comandos **uno por uno** en Terminal 2:

```powershell
python -m src.comunicaciones_seguras.tcp_client --username admin --operation admin_info
python -m src.comunicaciones_seguras.tcp_client --username consulta --operation status
python -m src.comunicaciones_seguras.tcp_client --username consulta --operation list_resources
```

Cada comando protegido solicita `Contraseña:`. Escribe la contraseña de ese usuario y presiona Enter. **Es normal que no se vean los caracteres al escribir.** No escribas la contraseña en la línea del comando ni la pegues después de `--operation`.

Resultados esperados:

| Usuario y operación | Resultado |
|---|---|
| `admin` + `admin_info` | `"result": "ok"` |
| `consulta` + `status` | `"result": "ok"` |
| `consulta` + `list_resources` | `"result": "denied"`, porque su rol no tiene ese permiso |

El administrador puede usar `admin_info`; el usuario `consulta` solo tiene permiso para `status`. El servidor determina los permisos; el cliente no envía su rol.

## 6. Ver la auditoría

En Terminal 2:

```powershell
Get-Content "$env:USERPROFILE\.infraestructura-comunicaciones-seguras\auth\audit.jsonl" -Tail 10
```

Debe haber eventos de acceso permitido y denegado. El archivo no debe contener contraseñas.

## 7. Comprobar el rechazo de certificados (opcional)

Estas pruebas deben fallar por diseño. Ejecuta una a la vez en Terminal 2 y restaura el valor correcto después de cada prueba:

```powershell
$base = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras"
$env:TLS_CA_FILE = "$base\pki\untrusted-ca\other-ca.crt"
python -m src.comunicaciones_seguras.tcp_client "Esta conexión debe rechazarse"
$env:TLS_CA_FILE = "$base\pki\ca\root-ca.crt"
```

La conexión debe rechazarse porque el cliente no confía en esa CA. Después prueba el nombre incorrecto:

```powershell
$env:TLS_SERVER_NAME = "servidor-falso.local"
python -m src.comunicaciones_seguras.tcp_client "Esta conexión también debe rechazarse"
$env:TLS_SERVER_NAME = "localhost"
```

También debe rechazarse por discrepancia de nombre. No desactives la validación para hacer pasar estas pruebas: el rechazo es el resultado correcto.

## 8. Ejecutar las pruebas automáticas

Detén el servidor con `Ctrl+C` en Terminal 1. En Terminal 2, ejecuta:

```powershell
Set-Location $project
$base = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras"
$env:TLS_TEST_CA_FILE = "$base\pki\ca\root-ca.crt"
$env:TLS_TEST_CERT_FILE = "$base\pki\server\server.crt"
$env:TLS_TEST_KEY_FILE = "$base\pki\server\server.key"
$env:TLS_TEST_SERVER_NAME = "localhost"
$env:TLS_TEST_UNTRUSTED_CA_FILE = "$base\pki\untrusted-ca\other-ca.crt"
python -m unittest discover -s tests -p "test*.py" -v
```

Busca `OK` al final. Si alguna prueba aparece como `skipped`, significa que no se ejecutó; no la cuentes como aprobada. Las pruebas de SSH requieren la configuración adicional de la guía completa.

## Solución rápida de errores comunes

- **`invalid choice: 'admin_infoCONTRASEÑA'`:** la contraseña se escribió pegada al comando. Vuelve a ejecutar el comando dejando solo `--operation admin_info`; escribe la contraseña únicamente cuando aparezca `Contraseña:`.
- **PowerShell muestra `Falta el nombre de tipo después de '['`:** probablemente pegaste el texto de ayuda `usage:` o `[--operation ...]`. No pegues la salida del error; ejecuta únicamente el comando de una línea indicado en esta guía.
- **`Conexión rechazada` o no conecta:** comprueba que Terminal 1 sigue ejecutando el servidor y que ambas terminales usan el puerto `5001`.
- **`TLS_CA_FILE` o certificado no encontrado:** repite el bloque de configuración TLS del cliente y verifica que `root-ca.crt` existe.
- **`servicio_no_disponible`:** revisa en Terminal 1 las rutas `AUTH_USERS_FILE` y `AUDIT_LOG_FILE`, y confirma que `users.json` existe.
- **`acceso_denegado` con `admin`:** verifica que estás usando la contraseña correcta del almacén externo de usuarios. No recrees todos los usuarios para solucionar una contraseña olvidada.
- **`usage: tcp_client.py`:** es la ayuda del programa, no un comando que debas copiar.

## Si olvidaste la contraseña

No uses `python -m src.comunicaciones_seguras.user_setup --overwrite`: esa opción reemplaza el archivo completo y recrea los tres usuarios. Usa la utilidad de restablecimiento, que actualiza solo la cuenta indicada y crea una copia de respaldo.

En una terminal PowerShell, ejecuta:

```powershell
$project = "C:\\Users\\brand\\OneDrive\\Documentos\\SDI\\infraestructura-comunicaciones-seguras"
Set-Location $project
$base = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras"
$env:AUTH_USERS_FILE = "$base\\auth\\users.json"
python -m src.comunicaciones_seguras.user_password_reset --username admin
```

Escribe y confirma la nueva contraseña cuando se solicite. No se mostrarán los caracteres. Para otra cuenta, cambia `admin` por `operador` o `consulta`. Después, reinicia el servidor en Terminal 1 con `Ctrl+C` y vuelve a ejecutar el bloque de inicio del servidor TLS; el servidor debe volver a cargar el almacén de usuarios actualizado. Luego prueba de nuevo la operación protegida desde Terminal 2.

El programa muestra la ruta del respaldo creado, pero nunca imprime la contraseña ni el hash. No compartas el contenido de `users.json`, las claves privadas ni las contraseñas en capturas o mensajes.

## Qué demuestra la ejecución

- TLS establece una conexión cifrada y el cliente valida la CA y el nombre del servidor.
- La autenticación comprueba las credenciales del usuario.
- La autorización aplica permisos según el rol en el servidor.
- La auditoría registra los intentos sin guardar contraseñas.

Este es un laboratorio educativo; no debe utilizarse como infraestructura de producción.
