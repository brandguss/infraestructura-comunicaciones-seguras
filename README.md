# Infraestructura de comunicaciones seguras

Aplicación en Python que representa la infraestructura de comunicaciones seguras de una pequeña organización. Incluye un cliente y un servidor, y muestra para qué sirve cada mecanismo de seguridad y en qué se diferencian: TLS con certificados digitales, una infraestructura de clave pública (PKI), administración remota con SSH, IPsec en modo transporte y túnel con protección contra replay, una VPN de acceso remoto y una VPN sitio a sitio, además de autenticación, autorización y auditoría.

Los mecanismos de protección de la sesión (TLS, PKI, SSH) son reales. IPsec y las dos VPN están simulados a nivel de software: su propósito es demostrar el funcionamiento y las diferencias, no construir protocolos de producción.

## Arquitectura

```
 Computadora cliente                        Computadora servidor
┌─────────────────────┐                  ┌────────────────────────────┐
│ tcp_client.py       │ ── TCP :5000 ──► │ tcp_server.py              │
│ (confía solo en la  │ ── TLS :5001 ──► │   auth.py (roles)          │
│  CA de laboratorio) │                  │   audit.py (registro)      │
│                     │                  │   ipsec_sim.py (opcional)  │
│ ssh_admin.py        │ ── SSH :22 ───►  │ sshd (OpenSSH, AllowUsers) │
└─────────────────────┘                  └────────────────────────────┘

Simulaciones (sin red real):
  vpn_sim.py ── RemoteAccessGateway  usuario ──► red privada, acceso según el rol
             └─ SiteToSiteVPN        red A ◄──► red B, paquetes IPSec simulados en modo túnel

PKI (OpenSSL):  CA raíz ──firma──► certificado del servidor ◄──valida── cliente
```

## Qué es real y qué es simulado

| Mecanismo | Implementación | Dónde |
|---|---|---|
| TCP cliente-servidor | Real (sockets) | `tcp_server.py`, `tcp_client.py` |
| TLS y certificados X.509 | Real (`ssl`, TLS 1.2 o superior) | `tcp_server.py`, `tcp_client.py` |
| CA y cadena de confianza | Real (OpenSSL) | Guía, sección 3 |
| SSH | Real (OpenSSH); el proyecto aporta el cliente administrativo y el registro | `ssh_admin.py`, guía sección 9 |
| IPsec (transporte, túnel, anti-replay) | **Simulado** (HMAC-SHA256 y ventana deslizante) | `ipsec_sim.py` |
| VPN de acceso remoto | **Simulada** | `vpn_sim.py` (`RemoteAccessGateway`) |
| VPN sitio a sitio | **Simulada** (opcionalmente real con strongSwan) | `vpn_sim.py` (`SiteToSiteVPN`), `docs/VPN_IPSEC_REAL_STRONGSWAN.md` |
| Autenticación, autorización y auditoría | Real | `auth.py`, `audit.py` |

## Qué hace cada mecanismo y en qué se diferencian

No resuelven el mismo problema: unos protegen una sesión entre dos programas, otros protegen tráfico entre redes o controlan quién entra a una red privada.

| Mecanismo | Objetivo | Qué protege | Cómo se identifica quién participa |
|---|---|---|---|
| TLS | Proteger una sesión cliente-servidor | Confidencialidad e integridad del mensaje | El servidor presenta un certificado firmado por una CA; el cliente lo valida |
| PKI | Establecer confianza entre identidades | La relación entre un nombre y una clave | Cadena de confianza hasta la CA raíz |
| SSH | Administrar equipos de forma remota | La sesión administrativa | Clave pública del usuario y clave del host |
| IPsec | Proteger paquetes IP entre dos puntos | Integridad, autenticidad y anti-replay de cada paquete | Clave compartida (SPI) entre los extremos |
| VPN de acceso remoto | Dar acceso de una persona a la red privada | La conexión de esa persona y sus privilegios | Usuario y contraseña; el rol limita los recursos |
| VPN sitio a sitio | Unir dos redes | Todo el tráfico permitido entre las subredes | Clave precompartida entre los gateways |

Autenticación y autorización son pasos distintos: la autenticación responde *quién eres*; la autorización, *qué puedes hacer*. Conectarse a la VPN autentica a la persona, pero no le da acceso a todo: cada recurso exige un rol.

## Requisitos previos

- Python 3.12 o superior. No hay dependencias de Python de terceros: solo se usa la biblioteca estándar.
- OpenSSL 3.x para crear la CA y los certificados.
- OpenSSH (cliente y servidor) para la parte de SSH.
- Dos computadoras en la misma red para demostrar el requisito de cliente y servidor separados.
- strongSwan solo si se quiere montar una VPN real (opcional).

## Cómo ejecutarlo

Toda la puesta en marcha en Windows con PowerShell está en la **[guía paso a paso](docs/GUIA_PASO_A_PASO_WINDOWS.md)**. Resumen del orden:

| Paso | Qué se hace | Guía |
|---|---|---|
| 1 | Clonar el repositorio y comprobar Python | Sección 1 |
| 2 | Crear la CA y el certificado del servidor con OpenSSL | Secciones 2 y 3 |
| 3 | Comparar TCP sin cifrar con TLS | Secciones 4 y 5 |
| 4 | Crear usuarios con roles y revisar la auditoría | Sección 6 |
| 5 | Rechazo de certificados y suite de pruebas | Sección 7 |
| 6 | IPsec simulado: modos y replay | Sección 8 |
| 7 | SSH autorizado y no autorizado | Sección 9 |
| 8 | Cliente y servidor en computadoras distintas | Sección 10 |
| 9 | VPN de acceso remoto y sitio a sitio | Sección 11 |

Una prueba rápida de TCP en una sola computadora (dos terminales en la raíz del repositorio). En la Terminal 1:

```powershell
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_server
```

En la Terminal 2:

```powershell
$env:COMMUNICATION_MODE = "tcp"
$env:TCP_HOST = "127.0.0.1"
$env:TCP_PORT = "5000"
python -m src.comunicaciones_seguras.tcp_client "Mensaje TCP de prueba"
```

La respuesta empieza por `RECIBIDO:`. Este canal no cifra nada. Con `127.0.0.1` ambos procesos están en la misma computadora; para el requisito de dos equipos, usa la sección 10 de la guía.

La demostración de las dos VPN no necesita configuración:

```powershell
python -m src.comunicaciones_seguras.vpn_demo
```

## TLS, certificados y PKI

El servidor se identifica con un certificado X.509 firmado por una CA de laboratorio creada con OpenSSL (`root-ca.crt`). El cliente solo confía en esa CA, exige TLS 1.2 como mínimo y valida tanto la firma como el nombre del servidor (SAN). Si la CA no es la esperada o el nombre no coincide, la conexión se rechaza antes de enviar ningún dato. Para demostrarlo, la guía genera también una segunda CA no confiable.

```
CA raíz (root-ca.crt) ──firma──► certificado del servidor (server.crt) ──presentado en TLS──► cliente
                     ▲                                                                         │
                     └──────────── el cliente confía solo en esta CA y verifica la cadena ◄────┘
```

Los certificados y las claves se guardan fuera del repositorio. La CA tiene `pathlen:0`: solo puede firmar certificados finales.

## Administración remota con SSH

Se usa OpenSSH real, configurado con tres controles: **autenticación** por clave pública (contraseñas desactivadas), **restricción** a usuarios autorizados con `AllowUsers`, y **registro** de intentos con `LogLevel VERBOSE`. El cliente administrativo `ssh_admin.py` exige verificar la clave del host, solo ejecuta comandos de una lista cerrada (`whoami`, `hostname`) y registra cada intento, aceptado o rechazado, en el mismo `audit.jsonl` que el resto de la aplicación. Los mensajes de error de OpenSSH se resumen para no filtrar rutas ni claves.

## IPsec simulado: transporte, túnel y replay

`ipsec_sim.py` encapsula cada mensaje en un paquete con SPI y número de secuencia, protegido con HMAC-SHA256.

- **Modo transporte:** un único encabezado con la carga.
- **Modo túnel:** un encabezado externo (gateway a gateway) que envuelve un paquete interno completo con origen, destino y carga.
- **Anti-replay:** ventana deslizante de 64 secuencias (configurable). Un paquete repetido, o demasiado antiguo, se rechaza y se registra como `ipsec_replay_duplicate` o `ipsec_replay_stale`. La ventana solo se modifica después de validar el HMAC, así que un atacante no puede agotarla con paquetes falsos.

El HMAC garantiza integridad y autenticidad, no confidencialidad: el contenido va en base64, no cifrado.

## VPN de acceso remoto y VPN sitio a sitio

Ambas están en `vpn_sim.py` y se diferencian por diseño. La demostración (`vpn_demo.py`) y las pruebas (`tests/test_vpn_sim.py`) las ejercitan.

**Acceso remoto (`RemoteAccessGateway`).** Una persona se autentica con usuario y contraseña, recibe una IP virtual del pool `10.30.0.0/24` y una sesión con vigencia. Conectarse no concede acceso ilimitado: cada recurso interno exige un rol.

| Recurso | Consulta | Operador | Administrador |
|---|---|---|---|
| `intranet-web` | Sí | Sí | Sí |
| `servidor-archivos` | No | Sí | Sí |
| `panel-administracion` | No | No | Sí |
| `base-datos` | No | No | Sí |

Después de tres contraseñas incorrectas la cuenta se bloquea temporalmente, aunque luego se use la contraseña correcta. Una sesión cerrada o vencida deja de servir.

**Sitio a sitio (`SiteToSiteVPN`).** Dos gateways conectan `10.10.0.0/24` y `10.20.0.0/24`. No hay usuarios: cualquier equipo de las subredes permitidas usa el túnel de forma transparente. Cada dirección tiene su propia asociación (clave derivada de la clave precompartida y SPI), los paquetes viajan en modo túnel, y el gateway de salida verifica el HMAC, descarta repetidos y aplica de nuevo la política de subredes. El tráfico hacia otro destino, o desde un origen que no pertenece a ningún sitio, se rechaza.

| | Acceso remoto | Sitio a sitio |
|---|---|---|
| Qué conecta | Un usuario con una red privada | Dos redes entre sí |
| Autenticación | Usuario y contraseña | Clave precompartida entre gateways |
| Autorización | Por rol, después de conectar | Por subredes de origen y destino |
| Direcciones | IP virtual por sesión | Los equipos conservan su IP |

## Autenticación, autorización y registro

`auth.py` guarda las contraseñas con scrypt y una sal aleatoria por usuario, y responde igual ante un usuario inexistente que ante una contraseña incorrecta. Los permisos se deciden siempre en el servidor según el rol, nunca con lo que envía el cliente:

| Rol | Operaciones |
|---|---|
| `administrador` | `status`, `list_resources`, `admin_info` |
| `operador` | `status`, `list_resources` |
| `consulta` | `status` |

Las operaciones autenticadas solo se aceptan sobre TLS, salvo que se habilite explícitamente un modo de laboratorio inseguro. `audit.py` escribe eventos JSON (una línea por evento) con fecha, usuario, operación, resultado (`allowed` o `denied`) y motivo, sin contraseñas ni tokens. Si la auditoría no está disponible, las operaciones protegidas se rechazan.

## Estructura del proyecto

| Ruta | Función |
|---|---|
| `src/comunicaciones_seguras/tcp_server.py` | Servidor TCP y TLS, solicitudes protegidas y respuestas |
| `src/comunicaciones_seguras/tcp_client.py` | Cliente TCP y TLS con validación del servidor |
| `src/comunicaciones_seguras/config.py` | Lectura y validación de la configuración desde variables de entorno |
| `src/comunicaciones_seguras/auth.py` | Usuarios, roles, autenticación y autorización |
| `src/comunicaciones_seguras/audit.py` | Registro de auditoría en JSON Lines |
| `src/comunicaciones_seguras/user_setup.py` | Crea los usuarios de prueba fuera del repositorio |
| `src/comunicaciones_seguras/ipsec_sim.py` | Simulación de IPsec: modos, HMAC y anti-replay |
| `src/comunicaciones_seguras/ipsec_key_setup.py` | Crea la clave externa de la simulación |
| `src/comunicaciones_seguras/vpn_sim.py` | VPN de acceso remoto y VPN sitio a sitio simuladas |
| `src/comunicaciones_seguras/vpn_demo.py` | Demostración de ambas VPN |
| `src/comunicaciones_seguras/ssh_admin.py` | Cliente administrativo SSH con registro de intentos |
| `tests/` | Pruebas automatizadas de TCP, TLS, autenticación, IPsec, SSH y VPN |
| `docs/GUIA_PASO_A_PASO_WINDOWS.md` | Instalación, ejecución y comprobación de cada requisito |
| `docs/VPN_IPSEC_REAL_STRONGSWAN.md` | Configuración de ejemplo para una VPN real |

## Pruebas

```powershell
python -m unittest discover -s tests -p "test*.py" -v
```

La suite cubre: TCP y TLS; validación y rechazo de certificados (nombre incorrecto y CA no confiable); autenticación, permisos por rol y auditoría; ambos modos de IPsec y la detección de replay, paquetes alterados y secuencias fuera de orden; SSH autorizado y no autorizado; y las dos VPN, incluidas las restricciones posteriores a la conexión.

Algunas pruebas dependen de material externo y se omiten si no está configurado: las de TLS con certificados necesitan las variables `TLS_TEST_*`, y las de integración SSH necesitan un servidor OpenSSH y `SSH_TEST_ENABLED=1`. Una prueba omitida no cuenta como aprobada: la sección 14 de la guía indica cómo ejecutar la suite completa sin omisiones y guardar el resultado como evidencia. El flujo de GitHub Actions ejecuta solo las pruebas que no necesitan ese material externo.

## Limitaciones de seguridad

Es un laboratorio educativo y **no debe usarse como infraestructura de producción**.

- **IPsec y VPN simulados:** no hay interfaces de red ni túneles del sistema operativo. El HMAC protege integridad y autenticidad, pero el contenido de los paquetes simulados no se cifra. El encabezado externo del modo túnel usa etiquetas fijas, y el estado anti-replay y las sesiones VPN viven en memoria: se pierden al reiniciar.
- **Gestión de claves:** la clave de la simulación y la clave precompartida no se negocian (no hay IKE ni intercambio de claves); se generan y se comparten fuera de banda.
- **Certificados de laboratorio:** la CA es de pruebas. En producción haría falta proteger la clave de la CA, controlar la emisión, revocar certificados (CRL u OCSP), renovarlos y usar una CA intermedia. No hay autenticación mutua de certificados: solo el servidor se identifica.
- **Contraseñas y sesiones:** hay bloqueo temporal en la VPN simulada, pero no en el servidor TCP/TLS, ni gestión de sesiones, doble factor o políticas de contraseña. Las credenciales de TCP/TLS se envían en cada solicitud (protegidas por TLS).
- **Secretos:** claves, usuarios y registros se guardan sin cifrar en archivos fuera del repositorio; su protección depende de los permisos del sistema. Nunca se deben subir a GitHub.
- **Auditoría:** los registros no son resistentes a manipulación; en producción se necesitarían almacenamiento centralizado, control de acceso, retención y protección contra modificación.
- **Disponibilidad:** el servidor atiende una conexión a la vez y se apoya en tiempos de espera; no está preparado para soportar ataques de denegación de servicio.
- **Red:** las pruebas sobre `127.0.0.1` solo comprueban conexiones dentro del mismo equipo. En una red real hay que limitar interfaces y puertos con el firewall, y emitir certificados con el nombre o la IP que usa el cliente.
- **SSH:** la seguridad depende de la configuración de OpenSSH (`AllowUsers`, contraseñas desactivadas, claves protegidas); el proyecto no la impone.
- **VPN real:** el código Python no crea túneles reales. La guía de strongSwan es una configuración externa opcional que debe adaptarse y verificarse con gateways reales.

## Documentación adicional

- [Guía paso a paso para Windows y PowerShell](docs/GUIA_PASO_A_PASO_WINDOWS.md)
- [VPN IPsec real con strongSwan (opcional)](docs/VPN_IPSEC_REAL_STRONGSWAN.md)
