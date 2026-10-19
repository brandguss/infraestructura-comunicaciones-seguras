# Infraestructura de comunicaciones seguras

Proyecto académico incremental para representar una infraestructura de comunicaciones seguras en una pequeña organización.

## Etapa 1: comunicación TCP sin protección

Esta etapa contiene un servidor TCP y un cliente TCP implementados exclusivamente con la biblioteca estándar de Python. El servidor recibe texto UTF-8 y responde con una confirmación. La comunicación es deliberadamente **sin cifrado**, para disponer de una base que posteriormente se comparará con TLS.

No se han implementado aún TLS, SSH, IPSec ni VPN.

## Requisitos detectados

- Python: `3.13.15` (comando `python`)
- Git: no disponible en el `PATH` durante la inspección
- OpenSSL: no disponible en el `PATH` durante la inspección

No se requieren paquetes externos.

## Estructura

```text
src/comunicaciones_seguras/
  config.py       # Configuración desde variables de entorno
  tcp_server.py   # Servidor TCP
  tcp_client.py   # Cliente TCP
tests/
  test_tcp.py     # Pruebas automatizadas locales
```

## Configuración

| Variable | Valor predeterminado | Uso |
| --- | --- | --- |
| `TCP_HOST` | `127.0.0.1` | Dirección en la que escucha el servidor o dirección del servidor para el cliente. |
| `TCP_PORT` | `5000` | Puerto TCP, entre 1 y 65535. |

Para una prueba local no es necesario configurar nada. Para usar dos equipos, inicie el servidor con una dirección de enlace accesible (por ejemplo `0.0.0.0`) y use en el cliente la IP real del equipo servidor. Asegúrese de que la red y el firewall permitan el puerto elegido.

## Ejecución local

Abra una terminal en la raíz del proyecto e inicie el servidor:

```powershell
python -m src.comunicaciones_seguras.tcp_server
```

En una segunda terminal, ejecute el cliente:

```powershell
python -m src.comunicaciones_seguras.tcp_client "Mensaje de prueba"
```

El cliente debe mostrar `RECIBIDO: Mensaje de prueba`. Para detener el servidor, presione `Ctrl+C`.

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

## Pruebas

Las pruebas usan `unittest`, incluido con Python:

```powershell
python -m unittest discover -s tests -v
```

## Seguridad y siguientes etapas

TCP en esta etapa transmite el contenido en claro; no debe utilizarse con datos sensibles. Las claves privadas, certificados con claves y registros se excluyen mediante `.gitignore`. Cuando se implemente la PKI, las claves se crearán fuera del repositorio.
