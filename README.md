# Infraestructura de comunicaciones seguras

Proyecto en Python para practicar comunicaciones TCP, conexiones TLS con certificados digitales, autenticación y autorización por roles, auditoría, administración remota mediante SSH y conceptos de IPsec. Incluye pruebas automatizadas y guías para preparar el entorno y verificar los resultados.

## Guías del proyecto: cuál seguir y en qué orden

**Empieza por la guía principal y sigue sus pasos en el orden indicado, desde el paso 1 hasta el final.** No necesitas leer ni ejecutar primero la guía de VPN.

1. **[Guía principal: instalación y ejecución paso a paso](docs/GUIA_PASO_A_PASO_WINDOWS.md)** — es el recorrido principal del proyecto. Sigue los pasos en orden; cada etapa explica qué preparar, qué comando ejecutar, qué resultado esperar y cómo comprobar si puedes continuar. Incluye TCP, TLS, certificados, usuarios, permisos, auditoría, SSH y pruebas. Si una prueba falla, detente en ese paso y revisa su solución antes de avanzar.
2. **[Guía complementaria: VPN IPsec con strongSwan](docs/VPN_IPSEC_REAL_STRONGSWAN.md)** — consúltala únicamente para configurar y comprobar una VPN IPsec real en gateways compatibles, si tu práctica requiere ese escenario. Es una configuración adicional que depende de equipos/redes y herramientas externas; no es necesaria para ejecutar las pruebas locales básicas y el programa Python no crea el túnel automáticamente.

**Importante:** las pruebas locales pueden ejecutarse en una computadora, pero no demuestran por sí solas la comunicación entre dos computadoras, la integración SSH real ni una VPN real. La guía principal indica cuándo interviene una configuración externa. Registra como comprobado únicamente aquello que hayas ejecutado y verificado.

## Arquitectura y objetivo de cada mecanismo

El proyecto separa los mecanismos porque no resuelven el mismo problema. TCP permite transportar mensajes, TLS protege la sesión entre cliente y servidor, la CA permite validar la identidad del servidor, SSH sirve para administración remota, y la simulación IPsec representa la protección de paquetes y el control anti-replay. La autenticación identifica al usuario; la autorización decide qué operaciones puede realizar; la auditoría deja constancia de las decisiones.

| Apartado | Qué se espera demostrar | Qué aporta y por qué se incluye |
|---|---|---|
| Cliente y servidor TCP | El cliente envía un mensaje y recibe respuesta. | Es la referencia inicial para comparar una conexión sin cifrado con TLS. |
| TLS | El cliente y el servidor establecen una sesión protegida. | Cifra el tráfico de la sesión y protege su integridad durante el transporte. |
| PKI y certificados | El cliente confía en la CA correcta y rechaza una CA desconocida o un nombre incorrecto. | Permite verificar la identidad del servidor, no solo cifrar la conexión. |
| SSH | Una cuenta autorizada se conecta usando OpenSSH y una clave de host verificada. | Proporciona administración remota protegida. La integración SSH requiere un servidor y credenciales configurados. |
| Simulación IPsec | Se pueden elegir los modos transporte y túnel y detectar paquetes alterados o repetidos. | Representa la protección de paquetes IP y la defensa contra replay sin implementar un protocolo de producción. |
| VPN de acceso remoto | El usuario se autentica y las operaciones disponibles dependen de su rol. | Representa la conexión de un equipo remoto a recursos internos con acceso limitado. Actualmente esta parte debe demostrarse mediante el escenario de simulación que se prepare; la guía strongSwan es una alternativa de túnel real, no un simulador Python. |
| VPN sitio a sitio | Se distingue una conexión entre dos redes detrás de gateways de una conexión de usuario remoto. | Representa la comunicación protegida entre redes diferentes. La guía describe un despliegue real, pero no lo crea automáticamente. |
| Autenticación, autorización y auditoría | Se prueban credenciales válidas e inválidas, permisos por rol y eventos registrados. | Distingue quién es el usuario, qué puede hacer y qué ocurrió durante el intento. |
| Pruebas | Las pruebas automatizadas confirman los comportamientos implementados y muestran los casos omitidos. | Permite repetir las comprobaciones y detectar regresiones. Las pruebas locales no demuestran por sí mismas una conexión entre dos computadoras ni una VPN real. |

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

## Dónde ejecutar cada paso

En las pruebas iniciales se pueden usar dos terminales de PowerShell en una sola computadora: la Terminal 1 mantiene el servidor abierto y la Terminal 2 ejecuta el cliente o las pruebas. Esta modalidad comprueba el intercambio básico, pero la dirección `127.0.0.1` siempre apunta al mismo equipo y **no satisface por sí sola el requisito de cliente y servidor en computadoras diferentes**.

Para demostrar la conexión entre dos computadoras, conecta ambos equipos a la misma red de laboratorio. En la computadora servidor, averigua la IP local con `ipconfig`, permite el puerto elegido en el firewall solo para la red privada y configura el servidor para escuchar en las interfaces de red. En la computadora cliente, configura `TCP_HOST` con la IP del servidor, no con `127.0.0.1`. Para TLS, el certificado del servidor debe incluir en su SAN el nombre DNS o la dirección IP que el cliente utilizará; el certificado local de ejemplo solo cubre `localhost` y `127.0.0.1`, por lo que hay que generar otro para la IP/nombre del servidor.

## 4. Orden recomendado para ejecutar el proyecto

**Esta lista resume el orden; no es una segunda guía con comandos alternativos.** Para ejecutar el proyecto, abre la [guía principal](docs/GUIA_PASO_A_PASO_WINDOWS.md) y sigue sus pasos numerados de principio a fin. Usa esta lista únicamente como índice de las etapas.

1. **Preparación:** instala Python, Git y OpenSSL; clona el repositorio y entra en la carpeta.
2. **Pruebas iniciales:** ejecuta las pruebas disponibles y revisa los casos omitidos.
3. **TCP:** inicia el servidor y después ejecuta el cliente; espera una respuesta que empiece por `RECIBIDO:`.
4. **TLS y PKI:** crea los certificados y verifica una conexión válida, el rechazo de una CA no confiable y el nombre del servidor.
5. **Usuarios, permisos y auditoría:** prueba una operación permitida y otra denegada, y comprueba los registros.
6. **Simulación IPsec:** comprueba integridad y anti-replay; recuerda que no es un túnel IPsec real.
7. **SSH:** configura el servidor, la clave pública y la confianza del host antes de ejecutar la prueba de integración.
8. **Suite final:** vuelve a ejecutar las pruebas y registra qué pasó, falló o se omitió.
9. **VPN real, si la actividad la requiere:** consulta la guía de strongSwan. Es un procedimiento externo que necesita gateways y redes configurados.

## 5. Preparación rápida (solo para clonar el repositorio)

Este bloque **solo descarga el proyecto**. No sustituye la guía principal ni constituye una segunda secuencia de pruebas. Si ya tienes el repositorio descargado, no lo clones otra vez: abre la carpeta local existente.

```powershell
git clone https://github.com/brandguss/infraestructura-comunicaciones-seguras.git
Set-Location infraestructura-comunicaciones-seguras
python --version
```

**Resultado esperado:** Git termina sin errores, se crea la carpeta `infraestructura-comunicaciones-seguras` y `python --version` muestra una versión compatible de Python. Si `python` no se reconoce, instala Python con la opción **Add Python to PATH** activada y reinicia la terminal.

**Siguiente paso obligatorio:** abre la [guía principal](docs/GUIA_PASO_A_PASO_WINDOWS.md) y continúa desde el paso 1. No ejecutes la suite inicial por separado aquí; la guía principal indica cuándo hacerlo y qué resultado comprobar.

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

## Cobertura actual de los requisitos

La mayor parte de los componentes principales está implementada y cuenta con pruebas de código: TCP, TLS, validación de certificados con material de prueba, autenticación, permisos, auditoría y la simulación IPsec. La suite ejecutada anteriormente terminó con 35 pruebas, sin fallos y con 2 omitidas; ese resultado corresponde a esa ejecución y no confirma pruebas externas que se hayan omitido.

Hay tres verificaciones que deben mantenerse separadas de ese resultado: (1) cliente y servidor en computadoras diferentes; (2) integración SSH con una prueba real de acceso permitido y rechazo de una cuenta/clave no autorizada, incluyendo los registros que exige la entrega; y (3) representación y pruebas específicas de VPN de acceso remoto y VPN sitio a sitio. La guía strongSwan permite preparar una VPN real, pero no equivale por sí sola a la simulación de ambos escenarios dentro de la aplicación. No se debe afirmar que estos puntos están comprobados hasta que se ejecute la prueba correspondiente.

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

## 13. Notas para reproducir los resultados

Las pruebas locales de TCP, TLS, autenticación y simulación se pueden ejecutar en una computadora. La integración SSH requiere un servidor y credenciales configurados. Una VPN real requiere dos extremos de red y su configuración. Guarda las salidas y capturas de cada comprobación para que se pueda identificar qué parte del proyecto se ejecutó y cuál depende de infraestructura externa.

## 14. Principales limitaciones de seguridad

Este proyecto es un laboratorio educativo y **no debe utilizarse como infraestructura de producción**. Sus principales límites son:

- **IPsec simulado:** `ipsec_sim.py` trabaja dentro de la aplicación Python; no implementa el protocolo IPsec del sistema operativo ni cifra el contenido del paquete. HMAC permite comprobar integridad/autenticidad con una clave compartida, pero no sustituye el cifrado.
- **VPN no creada automáticamente:** el código Python no establece un túnel VPN real. El acceso remoto y el escenario sitio a sitio deben presentarse como escenarios diferenciados y probarse explícitamente; la guía strongSwan es una configuración externa opcional y no evidencia por sí sola que el túnel funcione.
- **Alcance de las pruebas:** las pruebas locales no demuestran comunicación entre computadoras diferentes. Las pruebas de integración SSH requieren un servidor, usuarios, claves y confianza del host correctamente configurados. Cualquier prueba omitida debe reportarse como pendiente, no como aprobada.
- **Certificados de laboratorio:** la CA y los certificados son para pruebas. En un despliegue real se necesita proteger la clave privada de la CA, controlar su emisión y revocación, renovar certificados y mantener la clave privada del servidor fuera del repositorio.
- **Gestión de secretos:** las claves, contraseñas y archivos de usuarios deben protegerse con permisos adecuados y nunca publicarse en GitHub. Las claves de prueba no deben reutilizarse en producción.
- **Autenticación y autorización:** las cuentas y roles están diseñados para demostrar conceptos en un entorno controlado. Antes de un uso real se requiere revisar políticas de contraseñas, bloqueo/rate limiting, gestión de sesiones, privilegios mínimos y almacenamiento de secretos.
- **Auditoría:** los registros ayudan a revisar eventos, pero no son por sí solos un sistema de auditoría resistente a manipulación. En producción se necesitaría centralización, control de acceso, retención y protección contra modificación.
- **Red y firewall:** las pruebas sobre `127.0.0.1` solo verifican conexiones dentro del mismo equipo. La exposición en una red real requiere configurar firewall, limitar interfaces y puertos, verificar nombres/IP del certificado y evaluar la segmentación de red.

Por lo tanto, los resultados deben describirse según las pruebas que realmente se ejecutaron. La documentación y los ejemplos no equivalen a una certificación de seguridad ni a la validación de una VPN real.
