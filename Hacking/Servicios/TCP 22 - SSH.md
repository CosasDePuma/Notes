---
tags:
  - hacking
  - ssh
  - cve
---
**Secure Shell (SSH)**, es un protocolo de red que permite el acceso remoto seguro a servidores y otros dispositivos a través de una conexión cifrada. Su puerto estándar es `22/TCP`.

---
## Conexión

La autenticación basada en contraseña se puede efectuar mediante el siguiente comando:

```sh
ssh [usuario]@[host]
```

La autenticación basada en clave privada se puede efectuar mediante el siguiente comando:

```sh
# chmod 400 [clave_priv]
ssh -i [clave_priv] [usuario]@[host]
```

---
## Versión

Es posible obtener la versión en uso del servicio mediante el método `Banner Grabbing` usando cualquiera de los siguientes comandos:

```sh
ssh -vp [puerto] [host] 2>&1 | head -1
nc -nw 1 [host] [puerto]
nmap -sV -p [puerto] [host]
nxc ssh [host]
ssh-audit -p [puerto] [host]
terrapin-scanner -connect [host]:[puerto]
msfconsole -x 'use auxiliary/scanner/ssh/ssh_version'
```

---
## Cifrados

Para obtener un listado de los cifrados ofrecidos por el servidor, es posible utilizar cualquiera de los siguientes comandos:

```sh
ssh -vvp [puerto] [host] 2>&1 | grep -E '(ciphers stoc|KEX algo|MACs stoc)'
nmap --script ssh2-enum-algos -p [puerto] [host]
ssh-audit -p [puerto] [host]
```

>[!DANGER] Vulnerabilidades
>- [[Algoritmos KEX débiles habilitados]]
>- [[Algoritmos MAC débiles habilitados]]

### Terrapin (CVE-2023-48795)

Para comprobar si un servidor es vulnerable a Terrapin, se puede ejecutar cualquiera de los siguientes comandos:

```sh
terrapin-scanner -connect [host]:[puerto]
nuclei -id CVE-2023-48795 -u [host]:[puerto]
```

```cardlink
url: https://github.com/RUB-NDS/Terrapin-Scanner
title: "GitHub - RUB-NDS/Terrapin-Scanner: This repository contains a simple vulnerability scanner for the Terrapin attack present in the paper \"Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation\"."
description: "This repository contains a simple vulnerability scanner for the Terrapin attack present in the paper &quot;Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation&quot;. - R..."
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/67df18568bdbfd0bf8c4f6bcce01e5db84b25abc0d27e0a675141441b8c695cd/RUB-NDS/Terrapin-Scanner
```

```cardlink
url: http://github.com/projectdiscovery/nuclei-templates/blob/main/javascript/cves/2023/CVE-2023-48795.yaml
title: "nuclei-templates/javascript/cves/2023/CVE-2023-48795.yaml at main · projectdiscovery/nuclei-templates"
description: "Community curated list of templates for the nuclei engine to find security vulnerabilities. - projectdiscovery/nuclei-templates"
host: github.com
favicon: https://github.githubassets.com/favicons/favicon.svg
image: https://opengraph.githubassets.com/55a04f976b1f4b290cf36e12f9dc957616deba08186860d914915c937eca398e/projectdiscovery/nuclei-templates
```

>[!DANGER] Vulnerabilidades
>- [[Vulnerable a CVE-2023-48795 (Terrapin Attack)]]

---
## Métodos de autenticación

Con el fin de comprobar los métodos de autenticación disponibles,  es posible ejecutar cualquiera de los siguientes comandos:

```sh
ssh -vp [puerto] [host] 2>&1 | grep 'Authentications'
nmap --script ssh-auth-methods -p [puerto] [host]
nuclei -id ssh-password-auth -u [host]:[puerto] # solo password-based
```

Los métodos de autenticación más comunes son:

| Nombre               | Descripción                                                           |
| -------------------- | --------------------------------------------------------------------- |
| gssapi-keyex         | GSS-API con intercambio de claves (permite SSO, Kerberos, etc.)       |
| gssapi-with-mic      | GSS-API con Message Intregrity Check (permite SSO, Kerberos, etc.)    |
| hostbased            | Autenticación mediante par de claves criptográficas del host cliente. |
| keyboard-interactive | Autenticación basada en desafíos y respuestas como MFA o PAM.         |
| password             | Autenticación tradicional basada en nombre de usuario y contraseña.   |
| publickey            | Autenticación mediante par de claves criptográficas del usuario.      |

>[!DANGER] Vulnerabilidades
>- [[Autenticación basada en contraseña habilitada]]

### Enumeración de usuarios

Ciertas versiones de OpenSSH son vulnerables a enumeración de usuarios debido a una discrepancia en los tiempos de respuesta:

- [CVE-2018-15473](https://www.cve.org/CVERecord?id=CVE-2018-15473): Hasta la versión 7.7,  es posible la enumeración debido a que no se retrasa la salida de un usuario autenticado no válido.
- [CVE-2016-6210](https://www.cve.org/CVERecord?id=CVE-2016-6210): Hasta la versión 7.3, es posible la enumeración aprovechando la diferencia de tiempo entre las respuestas cuando se proporciona una contraseña grande, debido a que SHA256 o SHA512 se utilizan para hashear la contraseña de los usuarios existentes, mientras que BLOWFISH se utiliza para el hash de en una contraseña estática cuando el nombre de usuario no existe.

Es posible explotar estas vulnerabilidades mediante el siguiente comando:

```sh
msfconsole -x 'use auxiliary/scanner/ssh/ssh_enumusers'
```

>[!DANGER] Vulnerabilidades
>- [[Vulnerable a CVE-2016-6210 (User Enum)]]
>- [[Vulnerable a CVE-2018-15473 (User Enum)]]
