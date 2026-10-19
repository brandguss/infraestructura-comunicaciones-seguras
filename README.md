# Infraestructura de comunicaciones seguras

Proyecto académico que representa los mecanismos de comunicación y acceso seguro de una pequeña organización. El sistema utiliza un cliente y un servidor en Python para comparar TCP sin cifrar con TLS, validar identidades mediante certificados, aplicar autenticación y autorización, registrar eventos, comprobar administración remota mediante OpenSSH y estudiar conceptos de encapsulación IPsec.

> **Alcance académico:** TLS y la validación de certificados se implementan con las bibliotecas de Python. La integración SSH utiliza el cliente OpenSSH del sistema. IPsec es una simulación de software; las VPN de acceso remoto y sitio a sitio se describen como escenarios de arquitectura, no como túneles VPN reales. Este proyecto no debe utilizarse como infraestructura de producción.

## Requisitos

- Python 3.13 o compatible.
- OpenSSL 3.x para generar la PKI de pruebas.
- OpenSSH Client; OpenSSH Server solo para la prueba de integración SSH.
- No se requieren paquetes externos de Python: se usa la biblioteca estándar.

En Windows, si OpenSSL no está en PATH, se puede indicar su ruta mediante la variable `OPENSSL_EXE`.

## Arquitectura y estructura

### ¿Por qué existe esta estructura?

El proyecto separa cliente, servidor, autenticación, configuración, auditoría y simulación IPsec para que cada responsabilidad pueda estudiarse y probarse por separado. Esta separación ayuda a identificar qué componente establece la comunicación, cuál decide si una identidad puede ejecutar una operación y dónde queda evidencia de los eventos. La carpeta `tests` permite comprobar estos comportamientos sin depender siempre de una conexión externa.

```text
infraestructura-comunicaciones-seguras/
├── src/
│   └── comunicaciones_seguras/
│       ├── __init__.py
│       ├── config.py
│       ├── tcp_server.py
│       ├── tcp_client.py
│       ├── auth.py
│       ├── audit.py
│       ├── user_setup.py
│       ├── ipsec_sim.py
│       └── ipsec_key_setup.py
├── tests/
│   ├── test_tcp.py
│   ├── test_tls.py
│   ├── test_auth.py
│   ├── test_ssh.py
│   └── test_ipsec_sim.py
├── README.md
└── .gitignore
```

### ¿Para qué se creó cada archivo y carpeta?

| Archivo o carpeta | Para qué se hizo | Por qué es importante |
|---|---|---|
| `src/` | Contener el código fuente de la aplicación. | Separa la implementación del resto de archivos del proyecto. |
| `src/comunicaciones_seguras/` | Agrupar los módulos que forman el sistema de comunicaciones seguras. | Permite organizar el código por responsabilidades y ejecutar los módulos como paquete de Python. |
| `__init__.py` | Identificar el directorio como paquete de Python. | Facilita importar y ejecutar sus módulos con `python -m`. |
| `config.py` | Leer y validar opciones desde variables de entorno. | Permite cambiar puertos, modos, certificados y rutas sin modificar el código ni incrustar secretos. |
| `tcp_server.py` | Implementar el servidor TCP/TLS y procesar las operaciones recibidas. | Es el punto de entrada del lado servidor y permite comparar comunicación en claro y protegida por TLS. |
| `tcp_client.py` | Conectarse al servidor, enviar mensajes y solicitar operaciones. | Representa el extremo cliente y permite probar ambos modos de comunicación. |
| `auth.py` | Verificar credenciales y aplicar permisos según el rol. | Evita confiar en el rol declarado por el cliente y limita las operaciones autorizadas. |
| `audit.py` | Registrar eventos de seguridad en formato JSON Lines. | Facilita revisar conexiones, accesos permitidos y rechazos sin registrar contraseñas. |
| `user_setup.py` | Crear usuarios de demostración y guardar sal/hash de contraseña. | Facilita preparar el laboratorio sin almacenar contraseñas en texto plano. |
| `ipsec_sim.py` | Simular encapsulación, integridad HMAC y control anti-replay en modos transporte/túnel. | Permite estudiar estos conceptos sin afirmar que implementa un protocolo IPsec real. |
| `ipsec_key_setup.py` | Generar y guardar fuera del repositorio la clave de la simulación. | Separa la preparación de la clave del flujo normal del cliente/servidor. |
| `tests/` | Agrupar pruebas automatizadas. | Ayuda a comprobar funciones y detectar regresiones sin tener que probar todo manualmente. |
| `test_tcp.py` | Comprobar el comportamiento de comunicación TCP. | Valida el intercambio básico de mensajes. |
| `test_tls.py` | Comprobar los controles TLS y los escenarios de certificados cuando están configurados. | Ayuda a detectar fallos en la negociación y validación de identidad. |
| `test_auth.py` | Comprobar autenticación, roles y permisos. | Verifica que las operaciones dependan de credenciales y privilegios válidos. |
| `test_ssh.py` | Probar configuración y, si se habilita, la integración con OpenSSH. | Comprueba el uso de SSH sin implementar un servidor SSH propio. |
| `test_ipsec_sim.py` | Comprobar la simulación IPsec, la integridad y el rechazo de repetición. | Ayuda a validar que una carga alterada o repetida sea rechazada. |
| `README.md` | Documentar propósito, arquitectura, configuración, ejecución, pruebas y limitaciones. | Permite que otra persona entienda y reproduzca el laboratorio. |
| `.gitignore` | Excluir archivos locales y materiales sensibles o generados. | Reduce el riesgo de subir claves, certificados privados, configuraciones o artefactos de ejecución. |

> **Nota:** el diagrama refleja la estructura esperada del repositorio según los módulos documentados. Los certificados, claves privadas, usuarios de laboratorio y logs se generan fuera de esta estructura para no versionar datos sensibles.

## Matriz de cobertura de los 10 requisitos

### ¿Cómo se aborda cada requisito?

Los diez requisitos originales están **abordados dentro del alcance académico del proyecto** mediante una combinación de código funcional, pruebas automatizadas, integraciones configurables, simulación de protocolos y diseño documentado. Esto permite explicar qué mecanismo se utiliza, qué problema de seguridad resuelve y cómo se comprobaría. El nivel de implementación no es idéntico en todos los requisitos: cuando una función se presenta como simulación o diseño, se indica expresamente y no se afirma que exista un túnel de red real.

| # | Requisito de la actividad | Cómo se aborda en el proyecto | Alcance actual |
|---:|---|---|---|
| 1 | Comunicación cliente-servidor y comparación TCP/TLS, incluso entre equipos | Cliente y servidor en Python permiten comparar mensajes TCP en claro con una conexión TLS. El README describe la configuración de IP, puerto, firewall y nombre del certificado para una demostración entre dos computadoras. | Código disponible; la prueba entre equipos requiere configuración del entorno. |
| 2 | TLS, certificado del servidor y rechazo de certificados no confiables | El cliente configura una CA de confianza, verifica el certificado y valida el nombre del servidor; TLS 1.2 es el mínimo. Se documenta cómo preparar una CA alternativa para probar el rechazo. | Mecanismo implementado; ejecutar la integración con certificados externos para demostrarlo. |
| 3 | Crear una CA y certificados firmados, con cadena de confianza | Se incluyen comandos OpenSSL para generar una CA de laboratorio, una clave/certificado de servidor firmado y una CA no confiable de contraste. | Procedimiento documentado y reproducible; los archivos se generan localmente, fuera del repositorio. |
| 4 | Administración SSH, autenticación, restricciones y registro de intentos | La integración de pruebas utiliza OpenSSH existente, autenticación por clave y verificación estricta de la identidad del host. Los eventos de la aplicación se registran en auditoría; la prueba SSH requiere habilitar y configurar el servicio externo. | Integración preparada; requiere servidor, claves y configuración de laboratorio. |
| 5 | IPsec en modos transporte/túnel y protección contra repetición | El módulo de simulación IPsec representa ambos modos, valida integridad/autenticidad mediante HMAC-SHA256 y rechaza paquetes repetidos o fuera de la ventana permitida. | Simulación funcional con fines educativos; no es IPsec interoperable ni cifra la carga. |
| 6 | VPN de acceso remoto con usuario autenticado y acceso restringido | Se modela el flujo de usuario remoto, autenticación individual, autorización por rol y acceso únicamente a recursos permitidos. La aplicación implementa controles de identidad y permisos que forman parte de esa arquitectura. | Diseño funcional documentado; el programa no establece un túnel VPN real. |
| 7 | VPN sitio a sitio entre dos redes | Se documenta la arquitectura de dos gateways, las redes conectadas y el uso de rutas y políticas de tráfico entre subredes. | Diseño de arquitectura documentado; no configura gateways, rutas ni túneles reales. |
| 8 | Autenticación, autorización y auditoría | La aplicación verifica credenciales con scrypt, determina los roles en el servidor, restringe operaciones y registra eventos en formato JSON Lines. | Implementado para las operaciones de aplicación, con mejoras de endurecimiento pendientes. |
| 9 | Pruebas de TLS, certificados, SSH, IPsec, VPN y permisos | La suite unittest cubre comportamientos unitarios y de integración disponibles. Las pruebas externas dependen de PKI, OpenSSH y configuración local; los escenarios VPN se pueden explicar y evaluar a nivel de diseño, pero no como túneles ejecutados. | Cobertura parcial automatizada; las pruebas omitidas deben ejecutarse al preparar sus dependencias. |
| 10 | Documentar arquitectura, ejecución, mecanismos, diferencias y limitaciones | Este README explica componentes, comandos, variables de entorno, pruebas, propósito de cada mecanismo y diferencias entre código, simulación y arquitectura conceptual. | Documentación incluida. |

**Conclusión de cobertura:** la propuesta da respuesta a los diez puntos de la actividad a nivel de diseño académico y prototipo, y especifica el mecanismo previsto para cada uno. La cobertura documental de un requisito no equivale necesariamente a una implementación de red completa ni a una prueba ejecutada; las secciones de alcance actual identifican esas diferencias para que la demostración y la evaluación sean transparentes.

## Configuración por variables de entorno

### ¿Por qué se configura mediante variables de entorno?

Permite cambiar puertos, certificados y rutas de archivos sin editar el código ni guardar datos sensibles en el repositorio. También facilita ejecutar el mismo programa en distintas computadoras y preparar escenarios de laboratorio separados. Las rutas de claves privadas y credenciales deben apuntar a archivos externos protegidos.

| Variable | Predeterminado | Uso |
|---|---|---|
| `TCP_HOST` | `127.0.0.1` | Dirección de escucha del servidor o dirección del servidor para el cliente. |
| `TCP_PORT` | `5000` | Puerto TCP entre 1 y 65535. |
| `COMMUNICATION_MODE` | `tcp` | `tcp` o `tls`. |
| `TLS_CA_FILE` | — | Certificado público de la CA confiable para el cliente. |
| `TLS_CERT_FILE` | — | Certificado público del servidor. |
| `TLS_KEY_FILE` | — | Clave privada del servidor. |
| `TLS_SERVER_NAME` | valor de `TCP_HOST` | Nombre/IP validado contra el SAN del certificado. |
| `AUTH_USERS_FILE` | — | Archivo JSON externo con usuarios, sales y hashes scrypt. |
| `AUDIT_LOG_FILE` | — | Archivo externo JSON Lines de auditoría. |
| `SSH_TEST_ENABLED` | desactivado | Use `1` para habilitar la prueba SSH real. |
| `SSH_TEST_HOST` | — | Host OpenSSH de pruebas. |
| `SSH_TEST_USER` | — | Usuario SSH de pruebas. |
| `SSH_TEST_PRIVATE_KEY_FILE` | — | Ruta externa a la clave privada SSH. |
| `SSH_TEST_PORT` | `22` | Puerto SSH. |
| `SSH_TEST_TIMEOUT` | `15` | Tiempo límite de la prueba, de 1 a 60 segundos. |
| `SSH_TEST_KNOWN_HOSTS_FILE` | predeterminado de OpenSSH | Archivo externo opcional `known_hosts`. |
| `SSH_EXECUTABLE` | `ssh` | Ejecutable OpenSSH. |
| `IPSEC_SIM_ENABLED` | `0` | Active con `1` la simulación IPsec. |
| `IPSEC_SIM_KEY_FILE` | — | Archivo externo de clave simétrica de 32 bytes. |
| `IPSEC_SIM_SPI` | — | Identificador público de la asociación simulada. |
| `IPSEC_SIM_MODE` | `transport` | `transport` o `tunnel`. |
| `IPSEC_SIM_REPLAY_WINDOW` | `64` | Ventana anti-replay de 1 a 1024. |
| `IPSEC_SIM_MAX_MESSAGE_BYTES` | `2048` | Tamaño máximo de la carga protegida. |
| `IPSEC_SIM_SEQUENCE_START` | `1` | Secuencia inicial del emisor. |

TLS requiere una CA explícita, validación del certificado y del hostname, y TLS 1.2 como mínimo. No se debe desactivar ninguna de estas comprobaciones.

## Autenticación, autorización y auditoría

### ¿Qué problema resuelve esta sección?

La autenticación responde «¿quién intenta entrar?»; la autorización responde «¿qué puede hacer esa identidad?». Separarlas evita que un cliente se asigne privilegios por su cuenta y permite aplicar permisos distintos a administradores, operadores y usuarios de consulta. La auditoría ayuda a reconstruir conexiones y decisiones de acceso, y a investigar intentos rechazados sin registrar contraseñas ni claves.

Las operaciones protegidas envían usuario, contraseña y nombre de operación. El cliente no determina su propio rol: el servidor lo obtiene del archivo externo de usuarios. Las contraseñas se verifican con `hashlib.scrypt`, una sal aleatoria por usuario y `hmac.compare_digest`.

| Operación | Administrador | Operador | Consulta |
|---|---:|---:|---:|
| `status` | Sí | Sí | Sí |
| `list_resources` | Sí | Sí | No |
| `admin_info` | Sí | No | No |

Las credenciales incorrectas producen una respuesta pública genérica. Si falta la configuración necesaria o la auditoría no está disponible, las operaciones protegidas se rechazan. El eco TCP básico se conserva con fines académicos; **TCP no cifra el contenido** y no debe utilizarse para enviar credenciales o datos sensibles.

Cree las rutas externas y configure un usuario de demostración:

```powershell
$auth = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\auth"
$env:AUTH_USERS_FILE = Join-Path $auth "users.json"
$env:AUDIT_LOG_FILE = Join-Path $auth "audit.jsonl"
python -m src.comunicaciones_seguras.user_setup
```

La utilidad solicita la contraseña sin mostrarla y guarda solo la sal y el hash. No suba usuarios, hashes, sales, claves privadas ni auditorías a GitHub.

## TLS y PKI de pruebas con OpenSSL

### ¿Por qué se necesitan TLS y una PKI?

TLS protege la información durante el tránsito y permite que el cliente compruebe la identidad del servidor. La PKI aporta la relación de confianza: el certificado del servidor está firmado por una Autoridad Certificadora que el cliente reconoce. Probar una CA confiable y otra no confiable permite observar que la conexión no debe aceptarse solo porque el servidor presente cualquier certificado.

Mantenga todos los certificados, solicitudes y claves fuera del repositorio:

```powershell
$env:OPENSSL_EXE = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
$openssl = if (Get-Command openssl -ErrorAction SilentlyContinue) { "openssl" } else { $env:OPENSSL_EXE }
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
New-Item -ItemType Directory -Force "$pki\ca", "$pki\server", "$pki\untrusted-ca" | Out-Null
& $openssl genrsa -out "$pki\ca\root-ca.key" 4096
& $openssl req -x509 -new -sha256 -key "$pki\ca\root-ca.key" -days 3650 -out "$pki\ca\root-ca.crt" -subj "/CN=CA raiz academica" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign"
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

Para probar el rechazo de una CA no confiable, cree una CA diferente:

```powershell
& $openssl genrsa -out "$pki\untrusted-ca\other-ca.key" 2048
& $openssl req -x509 -new -sha256 -key "$pki\untrusted-ca\other-ca.key" -days 365 -out "$pki\untrusted-ca\other-ca.crt" -subj "/CN=CA no confiable de pruebas"
```

Configure el servidor TLS en una terminal:

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CERT_FILE = "$pki\server\server.crt"
$env:TLS_KEY_FILE = "$pki\server\server.key"
python -m src.comunicaciones_seguras.tcp_server
```

En otra terminal, configure el cliente TLS:

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:COMMUNICATION_MODE = "tls"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5001"
$env:TLS_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_SERVER_NAME = "localhost"
python -m src.comunicaciones_seguras.tcp_client "Mensaje TLS de prueba"
```

Para operaciones autenticadas sobre TLS, configure también `AUTH_USERS_FILE` y `AUDIT_LOG_FILE` en el servidor y ejecute el cliente, por ejemplo:

```powershell
python -m src.comunicaciones_seguras.tcp_client --username admin --operation admin_info
```

Para dos computadoras, el servidor debe escuchar en una dirección accesible (por ejemplo, `0.0.0.0`), el cliente debe usar la IP real del servidor y el certificado debe incluir el DNS/IP usado en su SAN. Configure el firewall de forma controlada; no deshabilite la validación del certificado.

## Administración remota mediante SSH

### ¿Para qué se utiliza SSH?

SSH está orientado a la administración remota segura de equipos. La autenticación por clave y la verificación de la clave del host ayudan a comprobar quién se conecta y a qué servidor se está conectando. Se incluye como una integración con OpenSSH existente para diferenciar la administración del equipo de la comunicación propia de la aplicación; no reemplaza TLS ni una VPN.

La integración ejecuta una prueba contra un servidor OpenSSH existente; el proyecto no implementa un servidor SSH propio ni modifica automáticamente el servicio, el firewall o las claves autorizadas. La prueba requiere autenticación por clave, `BatchMode`, `PasswordAuthentication=no` y `StrictHostKeyChecking=yes`. La clave del host debe estar previamente en `known_hosts`.

```powershell
$env:SSH_TEST_ENABLED = "1"
$env:SSH_TEST_HOST = "localhost"
$env:SSH_TEST_USER = "brand"
$env:SSH_TEST_PRIVATE_KEY_FILE = Join-Path $env:USERPROFILE ".ssh\id_ed25519_sdi"
$env:SSH_TEST_PORT = "22"
$env:SSH_TEST_TIMEOUT = "15"
python -m unittest tests.test_ssh.SSHIntegrationTests -v
```

La prueba está desactivada por defecto y se omite si no se habilita explícitamente. Si falla, compruebe OpenSSH Server, usuario, clave pública autorizada, clave privada, puerto y confianza de la clave del host. No quite la passphrase ni desactive la validación del host para hacer pasar la prueba. SSH protege la administración remota; no sustituye TLS de la aplicación ni una VPN.

## Simulación educativa de IPsec

### ¿Qué demuestra esta simulación?

Sirve para estudiar cómo un mecanismo de protección puede asociar metadatos y una carga a una asociación de seguridad, verificar su integridad y rechazar secuencias repetidas. Los modos transporte y túnel se representan con estructuras de datos para comparar sus propósitos. Se utiliza una simulación porque el objetivo académico es explicar esos conceptos, no implementar un protocolo IPsec interoperable a nivel de red.

Active esta funcionalidad solo para el laboratorio. Genera una clave aleatoria de 32 bytes y la guarda fuera del repositorio:

```powershell
$ipsec = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\ipsec"
$env:IPSEC_SIM_KEY_FILE = Join-Path $ipsec "ipsec_sim_key.json"
python -m src.comunicaciones_seguras.ipsec_key_setup
```

Configure la misma clave y asociación en el cliente y el servidor:

```powershell
$env:IPSEC_SIM_ENABLED = "1"
$env:IPSEC_SIM_KEY_FILE = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\ipsec\ipsec_sim_key.json"
$env:IPSEC_SIM_SPI = "laboratorio-2026-01"
$env:IPSEC_SIM_MODE = "transport" # o tunnel
$env:IPSEC_SIM_REPLAY_WINDOW = "64"
```

- **Transporte:** representa la protección de la carga interna.
- **Túnel:** representa una carga interna encapsulada con encabezados lógicos externos e internos.
- **Integridad/autenticación:** HMAC-SHA256 cubre los campos canónicos del paquete.
- **Anti-replay:** rechaza duplicados y secuencias demasiado antiguas; la ventana sincronizada permite cierto desorden de llegada.

Esta simulación no cifra la carga, no implementa ESP/AH ni IKE, no administra rutas o interfaces de red y no crea una VPN. La clave no debe imprimirse ni subirse al repositorio. El estado anti-replay vive en memoria; para reiniciar el laboratorio debe establecerse una asociación nueva y evitar reutilizar secuencias.

## Escenarios VPN representados conceptualmente

### ¿Por qué se distinguen dos tipos de VPN?

Ambos escenarios crean, en una implementación real, un canal protegido sobre una red no confiable, pero resuelven necesidades diferentes. El acceso remoto conecta a una persona o dispositivo y debe aplicar permisos según su identidad; sitio a sitio conecta redes a través de gateways y usa políticas de subredes y rutas. Separarlos permite explicar sus objetivos y controles sin afirmar que este programa crea túneles reales.

Las dos configuraciones siguientes explican objetivos y políticas distintas. **Son modelos de arquitectura para el análisis del proyecto, no conexiones implementadas por el programa actual.** No crean adaptadores virtuales, túneles, rutas ni acceso de red real.

### VPN de acceso remoto

```text
[Usuario remoto]
       |
       | Autenticación individual + túnel VPN (conceptual)
       v
[Gateway VPN de la organización]
       |
       | Política basada en el rol
       +----> [Recursos permitidos para Consulta]
       +----> [Recursos permitidos para Operador]
       +----> [Recursos administrativos restringidos]
```

Objetivo: conectar a un usuario individual desde una red externa. Después de autenticarse, la autorización debe limitarlo a los recursos de su rol; autenticarse no implica obtener acceso ilimitado. En una implementación real, el túnel y las rutas serían responsabilidad de un gateway VPN, mientras que la aplicación seguiría aplicando sus propios permisos.

### VPN sitio a sitio

```text
[Red de oficina A] -- [Gateway VPN A]
                            ||
                            || Túnel entre gateways (conceptual)
                            ||
[Red de oficina B] -- [Gateway VPN B]
```

Objetivo: conectar dos redes completas a través de gateways, normalmente mediante políticas de red y rutas entre subredes. No representa a un único usuario remoto y no se basa en asignarle recursos individuales de la misma manera que el acceso remoto. La autenticación de los gateways y las políticas de tráfico se configurarían en equipos VPN reales.

| Característica | Acceso remoto | Sitio a sitio |
|---|---|---|
| Extremos del túnel | Dispositivo/usuario y gateway | Gateway de red A y gateway de red B |
| Identidad principal | Usuario remoto | Gateways o extremos de red |
| Objetivo | Acceso individual a recursos autorizados | Comunicación entre subredes |
| Control de acceso | Usuario, rol y recursos permitidos | Subredes, rutas y políticas de tráfico |
| Estado en este proyecto | Conceptual/documental | Conceptual/documental |

## Ejecución TCP sin cifrar

### ¿Para qué sirve la prueba en claro?

Es una línea base para comparar el intercambio básico de mensajes con el intercambio protegido mediante TLS. Permite explicar que TCP transporta bytes, pero por sí solo no cifra los datos ni autentica la identidad del servidor. Debe usarse únicamente con mensajes de prueba, nunca con credenciales o información sensible.

En la raíz del repositorio, terminal del servidor:

```powershell
python -m src.comunicaciones_seguras.tcp_server
```

En otra terminal:

```powershell
python -m src.comunicaciones_seguras.tcp_client "Mensaje de prueba"
```

El eco TCP es útil para comparar el canal en claro con TLS. No envíe contraseñas ni información sensible por TCP sin cifrar.

## Pruebas automatizadas

### ¿Por qué se ejecutan estas pruebas?

Las pruebas automatizadas ayudan a detectar regresiones y comprobar comportamientos específicos, como rechazar credenciales incorrectas, detectar paquetes manipulados y bloquear repeticiones. Una prueba omitida indica que no se ejecutó por una condición del entorno; no debe contarse como aprobada. Por eso las integraciones que necesitan certificados o un servidor SSH deben configurarse y ejecutarse por separado.

La suite utiliza `unittest`, incluido con Python:

```powershell
python -m unittest discover -s tests -p "test*.py" -v
```

En la última ejecución registrada: **26 pruebas ejecutadas, 22 aprobadas, 4 omitidas y 0 fallidas**. Las omisiones correspondieron a la restricción del entorno para crear enlaces simbólicos, la falta de PKI externa para pruebas TLS y la integración SSH deshabilitada por defecto. Este resultado no demuestra por sí solo que las integraciones TLS y SSH externas estén completas.

Para habilitar pruebas TLS que requieren la PKI anterior:

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:TLS_TEST_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_TEST_CERT_FILE = "$pki\server\server.crt"
$env:TLS_TEST_KEY_FILE = "$pki\server\server.key"
$env:TLS_TEST_SERVER_NAME = "localhost"
$env:TLS_TEST_UNTRUSTED_CA_FILE = "$pki\untrusted-ca\other-ca.crt"
python -m unittest discover -s tests -p "test*.py" -v
```

Las pruebas SSH de configuración no necesitan una conexión. La integración SSH requiere OpenSSH Server y la configuración descrita en su sección. La integración TLS/IPsec requiere los archivos de PKI externos. Si faltan estas dependencias, las pruebas se reportan como omitidas, no como aprobadas.

## Limitaciones y consideraciones de seguridad

### ¿Por qué se documentan las limitaciones?

En seguridad es importante separar lo que el programa demuestra de lo que aún no garantiza. Explicitar los límites evita que los resultados académicos se interpreten como una certificación o como una solución apta para producción, y permite identificar qué necesitaría una implementación real antes de desplegarse.


- TCP sin cifrar expone el contenido a observadores de red.
- El informe de auditoría detectó que faltan controles adicionales para impedir operaciones autenticadas por TCP sin cifrar y limitar conexiones lentas; esos endurecimientos aún no están implementados.
- También quedan mejoras posibles en limitación de intentos, protección del archivo de usuarios e integridad/rotación de auditoría.
- La simulación IPsec solo aporta integridad/autenticación HMAC y anti-replay; no proporciona confidencialidad ni una VPN.
- Los escenarios VPN remoto y sitio a sitio son conceptuales y no establecen túneles de red.
- Las claves privadas, claves simétricas, certificados de prueba, hashes, sales y auditorías deben permanecer fuera del repositorio. En Windows, revise las ACL de los directorios externos.
- El proyecto es educativo y no ha sido certificado ni auditado como producto de producción.
