# Implementación de VPN IPsec real con strongSwan

Este documento complementa la simulación Python con una ruta para montar **IPsec real** en dos gateways Linux. No se puede validar un túnel real con una sola ejecución del cliente TCP: se necesitan dos extremos de red, interfaces/rutas y reglas de firewall. Los valores son de ejemplo y deben sustituirse por los de un laboratorio propio antes de ejecutar comandos.

## Topología de ejemplo sitio a sitio

| Elemento | Gateway A | Gateway B |
|---|---|---|
| IP pública/alcanzable del gateway | `198.51.100.10` | `203.0.113.20` |
| LAN detrás del gateway | `10.10.0.0/24` | `10.20.0.0/24` |
| Nombre de conexión | `site-to-site` | `site-to-site` |

Las direcciones `198.51.100.0/24` y `203.0.113.0/24` son rangos reservados para documentación: **no funcionarán en Internet**. Reemplázalas por direcciones alcanzables en tu laboratorio. No copies una PSK de ejemplo a un entorno real.

## 1. Instalar strongSwan en ambos gateways

En cada gateway Ubuntu/Debian, con permisos administrativos:

```bash
sudo apt update
sudo apt install strongswan
sudo systemctl enable --now strongswan-starter
sudo ipsec version
```

Antes de cambiar archivos, haz una copia de seguridad de la configuración existente. No sobrescribas una VPN que ya esté en uso.

## 2. Configurar Gateway A

Edita `/etc/ipsec.conf`:

```conf
config setup
    uniqueids= yes

conn site-to-site
    auto= start
    type= tunnel
    keyexchange= ikev2
    authby= secret
    ike= aes256-sha256-modp2048!
    esp= aes256-sha256!
    ikelifetime= 8h
    lifetime= 1h
    rekeymargin= 3m
    keyingtries= %forever
    dpdaction= restart
    dpddelay= 30s
    dpdtimeout= 120s
    left= 198.51.100.10
    leftid= 198.51.100.10
    leftsubnet= 10.10.0.0/24
    right= 203.0.113.20
    rightid= 203.0.113.20
    rightsubnet= 10.20.0.0/24
```

Edita `/etc/ipsec.secrets` y configura la misma clave precompartida fuerte en ambos gateways:

```conf
198.51.100.10 203.0.113.20 : PSK "REEMPLAZAR_POR_UN_SECRETO_ALEATORIO_LARGO"
```

Protege el archivo:

```bash
sudo chown root:root /etc/ipsec.secrets
sudo chmod 600 /etc/ipsec.secrets
```

## 3. Configurar Gateway B

Usa el mismo nombre de conexión y algoritmos, invirtiendo extremos y subredes en `/etc/ipsec.conf`:

```conf
config setup
    uniqueids= yes

conn site-to-site
    auto= start
    type= tunnel
    keyexchange= ikev2
    authby= secret
    ike= aes256-sha256-modp2048!
    esp= aes256-sha256!
    ikelifetime= 8h
    lifetime= 1h
    rekeymargin= 3m
    keyingtries= %forever
    dpdaction= restart
    dpddelay= 30s
    dpdtimeout= 120s
    left= 203.0.113.20
    leftid= 203.0.113.20
    leftsubnet= 10.20.0.0/24
    right= 198.51.100.10
    rightid= 198.51.100.10
    rightsubnet= 10.10.0.0/24
```

En `/etc/ipsec.secrets`, usa el mismo secreto fuerte, invirtiendo las IP:

```conf
203.0.113.20 198.51.100.10 : PSK "REEMPLAZAR_POR_EL_MISMO_SECRETO_ALEATORIO_LARGO"
```

## 4. Habilitar forwarding y firewall

En ambos gateways, habilita IPv4 forwarding de forma persistente según la política de red del laboratorio:

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-ipsec-forwarding.conf
sudo sysctl --system
```

Configura el firewall para permitir IKE/IPsec entre los gateways: UDP 500 y UDP 4500, y ESP (protocolo IP 50) cuando la topología lo requiera. Permite el forwarding solo entre las subredes autorizadas. No desactives el firewall ni abras servicios de administración a Internet. Si los gateways están detrás de NAT, se necesita revisar NAT-T y la topología específica.

## 5. Iniciar y comprobar el túnel

En ambos gateways:

```bash
sudo ipsec restart
sudo ipsec statusall
sudo ipsec trafficstatus
```

Desde un host de la LAN A, prueba una dirección real de un host permitido en LAN B, y viceversa. Comprueba que las rutas de retorno existan y que los firewalls de los hosts permitan la prueba. Un estado `ESTABLISHED` por sí solo no demuestra que el tráfico de aplicación llegue correctamente; valida tráfico en ambas direcciones y contadores de bytes.

Si falla, revisa `sudo journalctl -u strongswan-starter --since "10 minutes ago"`, la conectividad entre las IP de los gateways, las identidades configuradas, el secreto compartido, las rutas y las políticas de firewall. No publiques logs con secretos ni archivos `ipsec.secrets`.

## VPN de acceso remoto

La VPN de acceso remoto es otra topología: cada usuario se conecta desde un equipo cliente a un gateway, recibe una dirección del pool VPN y accede solo a las subredes autorizadas. Para implementarla de forma real se recomienda IKEv2 con certificados de servidor confiables y autenticación individual del usuario (por ejemplo EAP), no compartir una única PSK entre todos los usuarios. Debes preparar la CA/certificado del gateway, el método de autenticación de clientes, un pool de direcciones sin solapamiento, rutas y reglas de firewall; la configuración concreta depende del sistema cliente y del método de autenticación elegido.

No reutilices el ejemplo sitio a sitio como si fuera una configuración completa de acceso remoto. Tampoco copies una clave de ejemplo a producción. La prueba de aceptación debe confirmar: autenticación válida, rechazo de credenciales/certificados no válidos, asignación de IP VPN, acceso a recursos permitidos, bloqueo de recursos no autorizados y desconexión/revocación del usuario.

## Relación con el código Python

- `ipsec_sim.py` permite estudiar encapsulación, autenticación HMAC y anti-replay en el nivel de aplicación; no implementa el protocolo IPsec del kernel.
- strongSwan negocia asociaciones de seguridad IKE/IPsec y protege tráfico IP entre redes reales.
- TLS protege la conexión cliente-servidor de esta aplicación; una VPN y TLS tienen alcances distintos y pueden coexistir.
- La integración real de VPN debe probarse aparte de `python -m unittest`; las pruebas unitarias no crean gateways ni túneles automáticamente.

No marques los requisitos de VPN como demostrados hasta completar la configuración con direcciones reales del laboratorio y guardar evidencia del estado del túnel y del tráfico entre subredes.
