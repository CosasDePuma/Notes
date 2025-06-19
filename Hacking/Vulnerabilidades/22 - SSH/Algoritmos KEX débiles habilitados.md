---
tags:
  - hacking
  - vulnerabilities
  - ssh
---

|            | Información                                                         |
| ---------- | ------------------------------------------------------------------- |
| **Riesgo** | Bajo (0.9)                                                          |
| **CVSS**   | CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:U |

## Descripción

Se ha detectado que uno o más servicios SSH ofrecen algoritmos de intercambio de claves (KEX) que se consideran inseguros u obsoletos.

El algoritmo de intercambio de claves SSH es fundamental para mantener la seguridad del protocolo. Es lo que permite que dos partes previamente desconocidas generen una clave compartida a plena vista, y que ese secreto permanezca privado para el cliente y el servidor.

Hay tres razones principales por las que un algoritmo de intercambio se puede considerar débil:
1. El algoritmo utiliza SHA1.
2. El algoritmo utiliza claves RSA de módulo de 1024 bits o menor.
3. Se sospecha que la curva elíptica en uso ha sido vulnerada por la NSA (Agencia de Seguridad Nacional de los EE.UU.).

## Impacto

Un actor malicioso descifrar las comunicaciones SSH aprovechando las debilidades criptográficas de los algoritmos KEX obsoletos, afectando a la **confidencialidad** de los datos transmitidos.

Es importante destacar que este escenario de ataque tiene una probabilidad de explotación exitosa considerablemente reducida. El quebrantamiento de algoritmos criptográficos débiles requiere que el atacante sea capaz de interceptar las comunicaciones, así como una inversión elevada de recursos computacionales.

## Evidencias

Con el fin de comprobar los algoritmos de intercambio de claves ofrecidos, así como su robustez, se ha ejecutado el siguiente comando:

```sh
ssh-audit  -p [puerto] [host]
```

==EVIDENCIAS==

## Mitigaciones

Se recomienda configurar el servidor SSH para ofrecer solamente los siguientes algoritmos KEX:

```
curve25519-sha256@libssh.org
diffie-hellman-group16-sha512
diffie-hellman-group18-sha512
```

En OpenSSH es posible configurar estos algoritmos modificando la opción `KexAlgorithms` alojada en el archivo `/etc/ssh/sshd_config`.

## Referencias

- https://datatracker.ietf.org/doc/html/rfc8308/
- https://datatracker.ietf.org/doc/html/rfc9142
- https://cwe.mitre.org/data/definitions/327.html
- https://capec.mitre.org/data/definitions/217.html
- https://attack.mitre.org/techniques/T1557/