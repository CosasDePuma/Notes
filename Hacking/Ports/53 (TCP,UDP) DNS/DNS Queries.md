# Teoria

Las consultas #DNS(_DNS queries_) permiten obtener información sobre la infraestructura de red mediante la resolución de diferentes tipos de registros DNS.

Los tipos de registros más relevantes son:

| Tipo  | Descripción                                  |
| ----- | -------------------------------------------- |
| A     | Dirección IPv4                               |
| AAAA  | Dirección IPv6                               |
| CNAME | Alias                                        |
| MX    | Servidores de correo                         |
| NS    | Servidores de nombres autoritativos          |
| PTR   | Resolución inversa (IP a nombre)             |
| SOA   | Información sobre la zona DNS                |
| SRV   | Servicios disponibles                        |
| TXT   | Registros de texto (SPF, DKIM, metadatos...) |

>[!tip] En entornos **Active Directory**, los registros SRV son especialmente valiosos para identificar controladores de dominio y servicios críticos.

# Enumeración

Es posible consultar el servidor DNS mediante los siguientes comandos:

~~~tabs

tab: dig

<span query="codeBlock(_/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, code = dig {{domain}} @{{rhost}} A&#10;dig {{domain}} @{{rhost}} AAAA&#10;dig {{domain}} @{{rhost}} CNAME&#10;dig {{domain}} @{{rhost}} MX&#10;dig {{domain}} @{{rhost}} NS&#10;dig {{domain}} @{{rhost}} TXT, lang = )"></span>
``` 
dig ${DOMAIN} @${RHOST} A
dig ${DOMAIN} @${RHOST} AAAA
dig ${DOMAIN} @${RHOST} CNAME
dig ${DOMAIN} @${RHOST} MX
dig ${DOMAIN} @${RHOST} NS
dig ${DOMAIN} @${RHOST} TXT
```
<span type="end"></span>


tab: host

<span query="codeBlock(_/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, code = host -t A {{domain}} {{rhost}}&#10;host -t AAAA {{domain}} {{rhost}}&#10;host -t CNAME {{domain}} {{rhost}}&#10;host -t MX {{domain}} {{rhost}}&#10;host -t NS {{domain}} {{rhost}}&#10;host -t TXT {{domain}} {{rhost}}, lang = )"></span>
``` 
host -t A ${DOMAIN} ${RHOST}
host -t AAAA ${DOMAIN} ${RHOST}
host -t CNAME ${DOMAIN} ${RHOST}
host -t MX ${DOMAIN} ${RHOST}
host -t NS ${DOMAIN} ${RHOST}
host -t TXT ${DOMAIN} ${RHOST}
```
<span type="end"></span>


tab: nslookup

<span query="codeBlock(_/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, _/variables/hacking.md/domain, _/variables/hacking.md/rhost, code = nslookup {{domain}} {{rhost}} -type=A&#10;nslookup {{domain}} {{rhost}} -type=AAAA&#10;nslookup {{domain}} {{rhost}} -type=CNAME&#10;nslookup {{domain}} {{rhost}} -type=MX&#10;nslookup {{domain}} {{rhost}} -type=NS&#10;nslookup {{domain}} {{rhost}} -type=TXT, lang = )"></span>
``` 
nslookup ${DOMAIN} ${RHOST} -type=A
nslookup ${DOMAIN} ${RHOST} -type=AAAA
nslookup ${DOMAIN} ${RHOST} -type=CNAME
nslookup ${DOMAIN} ${RHOST} -type=MX
nslookup ${DOMAIN} ${RHOST} -type=NS
nslookup ${DOMAIN} ${RHOST} -type=TXT
```
<span type="end"></span>

~~~

En entornos de **Directorio Activo**, es posible enumerar recursos mediante las siguientes consultas SRV:

=== #TODO ===
