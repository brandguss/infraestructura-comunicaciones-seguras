# Infraestructura de comunicaciones seguras

Proyecto en Python para practicar comunicaciones TCP, conexiones TLS con certificados digitales, autenticación y autorización por roles, auditoría, administración remota mediante SSH y conceptos de IPsec. Incluye pruebas automatizadas y guías para preparar el entorno y verificar los resultados.

## Guías del proyecto

- **[Guía principal: instalación y ejecución paso a paso](docs/GUIA_PASO_A_PASO_WINDOWS.md)**. Explica qué instalar, qué comando ejecutar en cada terminal, para qué sirve cada paso, qué resultado esperar y cómo resolver errores. Incluye TCP, TLS, certificados, usuarios, permisos, auditoría, SSH y pruebas.
- **[Guía de VPN IPsec con strongSwan](docs/VPN_IPSEC_REAL_STRONGSWAN.md)**. Contiene ejemplos para VPN sitio a sitio y acceso remoto, junto con configuración de gateways, forwarding, firewall y comprobaciones del túnel.

## 1. Tecnologías y herramientas utilizadas

| Tecnología o herramienta | Uso en el proyecto |
|---|---|
| **Python 3.13** | Lenguaje principal de la aplicación y de las pruebas automatizadas. |
| **Sockets TCP (`socket`)** | Comunicación entre cliente y servidor. |
| **TLS/SSL (`ssl`)** | Protección de la conexión, negociación TLS y validación del certificado del servidor. |
| **Certificados X.509 y CA** | Identificación del servidor y verificación de confianza en las pruebas TLS. |
| **OpenSSL** | Generación de la CA de laboratorio, certificados, claves y certificados de prueba. Es una herramienta externa, no un paquete de Python. |
| **JSON (`json`)** | Formato de los mensajes de operaciones protegidas, los paquetes de la simulación y los registros de auditoría. |
| **HMAC-SHA256 (`hmac`, `hashlib`)** | Verificación de integridad y autenticidad en la simulación didáctica de IPsec. |
| **Base64 (`base64`)** | Codificación del contenido de los paquetes simulados. No es cifrado. |
| **Scrypt (`hashlib.scrypt`)** | Derivación de hashes para almacenar contraseñas de los usuarios de prueba. |
| **Hilos y bloqueos (`threading`)** | Coordinación de las pruebas de conexión y control del estado anti-replay de la simulación. |
| **OpenSSH** | Cliente/servidor SSH para la prueba de integración remota, si se configura el entorno necesario. |
| **strongSwan / IPsec** | Herramienta opcional para configurar una VPN real en gateways Linux siguiendo la guía correspondiente. No se instala ni se inicia desde el programa Python. |
| **Git y GitHub** | Control de versiones, alojamiento del código y ejecución de la suite automatizada mediante GitHub Actions. |
| **PowerShell** | Terminal utilizada en los pasos de instalación y pruebas de Windows. |

## 2. Paquetes y dependencias de Python

El proyecto utiliza la **biblioteca estándar de Python**; no necesita instalar paquetes externos con `pip` para ejecutar la aplicación y las pruebas actuales. Los módulos principales son:

| Módulo | Para qué se utiliza |
|---|---|
| `socket` | Crear conexiones TCP y escuchar conexiones entrantes. |
| `ssl` | Crear contextos TLS y comprobar certificados y nombres de servidor. |
| `json` | Serializar y analizar solicitudes, respuestas y paquetes de la simulación. |
| `hashlib` | Calcular SHA-256 y derivar hashes de contraseñas con Scrypt. |
| `hmac` | Calcular y verificar etiquetas de autenticación en la simulación IPsec. |
| `base64` | Codificar y decodificar contenido de los paquetes simulados. |
| `threading` | Ejecutar partes de las pruebas de conexión y proteger secciones críticas. |
| `argparse` | Procesar argumentos del cliente desde la terminal. |
| `getpass` | Solicitar contraseñas sin mostrarlas en pantalla. |
| `logging` | Informar de conexiones, errores y eventos operativos. |
| `unittest` | Ejecutar las pruebas automáticas sin instalar un framework de pruebas externo. |
| `pathlib`, `os`, `dataclasses`, `typing` | Manejar rutas, variables de entorno, configuración y tipos de datos. |

No existe un archivo `requirements.txt` porque no hay dependencias de terceros de Python que instalar para el funcionamiento actual. OpenSSL, Git y OpenSSH son programas del sistema; strongSwan es opcional y se utiliza para el escenario de VPN real.

## 3. Qué necesitas antes de comenzar

- Windows 10/11 con PowerShell o un entorno compatible.
- Python 3.13 o una versión compatible con el código.
- Git para clonar el repositorio.
- OpenSSL 3.x para crear los certificados de laboratorio.
- OpenSSH Client para utilizar el cliente SSH; la prueba de integración requiere además un servidor accesible y una cuenta configurada.
- Para una VPN real: dos gateways o extremos de red compatibles con strongSwan/IPsec y acceso para configurar rutas y firewall.

## 4. Orden recomendado para ejecutar el proyecto

Sigue los pasos en este orden y usa la [guía principal](docs/GUIA_PASO_A_PASO_WINDOWS.md) para ver todos los comandos y las explicaciones de cada uno.

1. **Prepara el entorno.** Instala Python, Git y OpenSSL. Abre PowerShell y clona el repositorio.
2. **Ejecuta las pruebas iniciales.** Comprueba que Python encuentra el proyecto y revisa qué pruebas pueden ejecutarse antes de configurar certificados y SSH.
3. **Prueba TCP.** Abre dos terminales, inicia el servidor en una y ejecuta el cliente en la otra. La respuesta debe empezar por `RECIBIDO:`.
4. **Genera los certificados y prueba TLS.** Crea una CA de laboratorio y el certificado del servidor. Comprueba la conexión válida y que el cliente rechace una CA no confiable o un nombre incorrecto.
5. **Configura usuarios y permisos.** Crea las cuentas de prueba, inicia el servidor con las rutas de configuración correctas y compara una operación permitida con otra que el rol no puede ejecutar.
6. **Revisa la auditoría.** Comprueba que se registren los eventos permitidos y rechazados sin almacenar contraseñas.
7. **Prueba la simulación IPsec.** Ejecuta las pruebas de encapsulación, integridad y anti-replay. Este componente es una simulación a nivel de aplicación, no una VPN del sistema operativo.
8. **Configura SSH si necesitas demostrarlo.** Autoriza una clave pública en el servidor, verifica la clave de host y ejecuta la prueba de integración.
9. **Ejecuta de nuevo la suite completa.** Configura las variables de entorno de las pruebas TLS, revisa los casos omitidos y guarda el resultado.
10. **Configura la VPN real si forma parte de los requisitos.** Sigue la [guía de strongSwan](docs/VPN_IPSEC_REAL_STRONGSWAN.md). Necesitas gateways y redes de laboratorio; ejecutar el programa Python no crea el túnel.

## 5. Instalación rápida

En PowerShell, clona el repositorio y entra en la carpeta:

```powershell
git clone https://github.com/brandguss/infraestructura-comunicaciones-seguras.git
Set-Location infraestructura-comunicaciones-seguras
python --version
git status --short
```

Si ya tienes el proyecto descargado, entra a la carpeta local existente en lugar de clonarlo otra vez. Si `python` no se reconoce, instala Python con la opción **Add Python to PATH** activada y reinicia la terminal.

Ejecuta la suite inicial:

```powershell
python -m unittest discover -s tests -p "test*.py" -v
```

Algunas pruebas de integración se omiten hasta que existan los certificados o la configuración SSH requerida. Una prueba omitida no confirma que esa función haya sido validada.

## 6. Prueba rápida de TCP

Abre dos terminales PowerShell en la raíz del repositorio. En la **Terminal 1**, inicia el servidor:

```powershell
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_server
```

Deja esa terminal abierta. En la **Terminal 2**, envía un mensaje:

```powershell
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_client "Mensaje TCP de prueba"
```

El cliente debe mostrar una respuesta que comience con `RECIBIDO:`. Esta prueba confirma el intercambio básico de datos; TCP por sí solo no cifra el mensaje. Detén el servidor con `Ctrl+C`.

## 7. Componentes del proyecto

| Archivo | Responsabilidad |
|---|---|
| `src/comunicaciones_seguras/config.py` | Lee y valida las variables de entorno. |
| `src/comunicaciones_seguras/tcp_server.py` | Servidor TCP/TLS, recepción de solicitudes, control de operaciones y respuestas. |
| `src/comunicaciones_seguras/tcp_client.py` | Cliente TCP/TLS y envío de solicitudes protegidas. |
| `src/comunicaciones_seguras/auth.py` | Almacenamiento de usuarios de laboratorio, autenticación y autorización por roles. |
| `src/comunicaciones_seguras/audit.py` | Registro de eventos de seguridad en formato JSON Lines. |
| `src/comunicaciones_seguras/user_setup.py` | Herramienta para preparar usuarios de prueba. |
| `src/comunicaciones_seguras/ipsec_sim.py` | Simulación de paquetes, HMAC e identificación de mensajes repetidos. |
| `src/comunicaciones_seguras/ipsec_key_setup.py` | Preparación de la clave externa para la simulación IPsec. |
| `tests/test_tcp.py` | Pruebas del transporte TCP. |
| `tests/test_tls.py` | Pruebas TLS con certificados externos de laboratorio. |
| `tests/test_auth.py` | Pruebas de autenticación y permisos. |
| `tests/test_ipsec_sim.py` | Pruebas de la simulación IPsec. |
| `tests/test_ssh.py` | Pruebas de integración SSH sujetas a configuración externa. |
| `docs/GUIA_PASO_A_PASO_WINDOWS.md` | Procedimiento principal para instalar, ejecutar y comprobar el proyecto. |
| `docs/VPN_IPSEC_REAL_STRONGSWAN.md` | Configuración de ejemplo para una VPN real con strongSwan. |

## 8. Funciones y cómo se comprueban

| Función | Comprobación esperada |
|---|---|
| TCP cliente-servidor | El cliente recibe la respuesta `RECIBIDO:`. |
| TLS | La conexión se establece con un certificado confiable y el cliente valida el nombre del servidor. |
| Validación de certificados | Se rechaza el nombre incorrecto y una CA no confiable. |
| Autenticación | Una cuenta válida puede autenticarse; las credenciales incorrectas no permiten ejecutar la operación. |
| Autorización | Las operaciones permitidas por el rol se aceptan y las no permitidas se rechazan. |
| Auditoría | Se registran eventos de aceptación/rechazo sin contraseñas. |
| Simulación IPsec | Las pruebas verifican integridad y rechazo de mensajes repetidos; no demuestra un túnel real. |
| SSH | La prueba de integración funciona cuando el servidor, la cuenta, la clave y la confianza del host están configurados. |
| VPN IPsec real | Se valida por separado con dos extremos de red, estado del túnel y tráfico entre subredes. |

## 9. Configuración y archivos externos

Los certificados, claves, usuarios y registros de prueba se guardan fuera de la carpeta del repositorio, en el perfil del usuario de Windows. La guía principal incluye los comandos para crear y configurar estas rutas y las variables de entorno que necesitan el servidor, el cliente y las pruebas.

No subas claves privadas, contraseñas, archivos de usuarios ni registros con datos sensibles a GitHub. Si una variable de entorno se configura en PowerShell, solo estará disponible en esa terminal y en los procesos que se inicien desde ella.

## 10. Pruebas automatizadas

Para ejecutar toda la suite:

```powershell
python -m unittest discover -s tests -p "test*.py" -v
```

Para las pruebas TLS que requieren los certificados de laboratorio, configura las variables en la misma terminal:

```powershell
$pki = Join-Path $env:USERPROFILE ".infraestructura-comunicaciones-seguras\pki"
$env:TLS_TEST_CA_FILE = "$pki\ca\root-ca.crt"
$env:TLS_TEST_CERT_FILE = "$pki\server\server.crt"
$env:TLS_TEST_KEY_FILE = "$pki\server\server.key"
$env:TLS_TEST_SERVER_NAME = "localhost"
$env:TLS_TEST_UNTRUSTED_CA_FILE = "$pki\untrusted-ca\other-ca.crt"
python -m unittest discover -s tests -p "test*.py" -v
```

Revisa el resumen al final: debe indicar cuántas pruebas se ejecutaron, cuántas fallaron y cuántas se omitieron. Las pruebas SSH y VPN dependen de sistemas externos y no se consideran comprobadas por una suite unitaria local.

Para guardar la salida de la suite como evidencia:

```powershell
python -m unittest discover -s tests -p "test*.py" -v 2>&1 | Tee-Object -FilePath ".\resultado_pruebas.txt"
```

## 11. Alcance de la simulación IPsec y de las VPN

El módulo `ipsec_sim.py` representa conceptos de encapsulación, autenticación mediante HMAC y control anti-replay dentro de la aplicación Python. HMAC permite detectar modificaciones y autenticar el paquete si la clave es compartida, pero **no cifra el contenido** y el módulo no implementa el protocolo IPsec del sistema operativo.

Para probar una VPN real, configura strongSwan u otra implementación IPsec en los gateways, define direcciones, subredes, autenticación, rutas y reglas de firewall, y verifica que los paquetes de prueba pasen por el túnel. La guía de VPN proporciona ejemplos de configuración que deben adaptarse al laboratorio. La prueba de acceso remoto y la prueba sitio a sitio son escenarios diferentes.

## 12. Lista de verificación para la entrega

- [ ] El servidor TCP inicia y el cliente recibe la respuesta esperada.
- [ ] La conexión TLS funciona con el certificado correcto.
- [ ] TLS rechaza un nombre de servidor incorrecto y una CA no confiable.
- [ ] La autenticación distingue credenciales válidas e inválidas.
- [ ] La autorización permite o rechaza operaciones según el rol.
- [ ] La auditoría registra los resultados sin almacenar contraseñas.
- [ ] Las pruebas de la simulación IPsec, incluida la protección anti-replay, pasan.
- [ ] La suite completa termina sin fallos; los casos omitidos están identificados.
- [ ] La prueba SSH se ejecuta si el entorno de integración está configurado.
- [ ] La VPN real se marca como comprobada solo después de establecer el túnel y validar tráfico entre redes.

## 13. Notas para reproducir los resultados

Las pruebas locales de TCP, TLS, autenticación y simulación se pueden ejecutar en una computadora. La integración SSH requiere un servidor y credenciales configurados. Una VPN real requiere dos extremos de red y su configuración. Guarda las salidas y capturas de cada comprobación para que se pueda identificar qué parte del proyecto se ejecutó y cuál depende de infraestructura externa.
