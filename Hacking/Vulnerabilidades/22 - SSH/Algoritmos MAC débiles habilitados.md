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

Se ha detectado que uno o más servicios SSH ofrecen algoritmos de código de autenticación de mensajes (MAC) que se consideran inseguros u obsoletos.

El algoritmo MAC en SSH es fundamental para mantener la seguridad del protocolo. Es el responsables de verificar que los datos transmitidos no hayan sido modificados durante el tránsito y que provengan de la fuente legítima, proporcionando protección contra ataques de manipulación de datos.

Hay cuatro razones principales por las que un algoritmo de código de autenticación de mensajes se puede considerar débil:

1. Se utiliza una función hash débil conocida (como MD5, SHA1 o RIPEMD).
2. La longitud _digest_ es demasiado pequeña (menos de 128 bits).
3. El tamaño de la etiqueta es demasiado pequeño (menos de 128 bits).
4. No utiliza el esquema Encrypt-then-MAC (EtM).

## Impacto

Un actor malicioso podría manipular las comunicaciones SSH aprovechando las debilidades criptográficas de los algoritmos MAC obsoletos, afectando a la **integridad** de los datos transmitidos.

Es importante destacar que este escenario de ataque tiene una probabilidad de explotación exitosa considerablemente reducida. El quebrantamiento de algoritmos de código de autenticación de mensajes débiles requiere que el atacante sea capaz de interceptar las comunicaciones, así como una inversión elevada de recursos computacionales.

## Evidencias

Con el fin de comprobar los algoritmos de código de autenticación de mensajes ofrecidos, así como su robustez, se ha ejecutado el siguiente comando:

```sh
ssh-audit -p [puerto] [host]
```

==EVIDENCIAS==

## Mitigaciones

Se recomienda configurar el servidor SSH para ofrecer solamente los siguientes algoritmos MAC:

```
hmac-sha2-512-etm@openssh.com
hmac-sha2-256-etm@openssh.com
umac-128-etm@openssh.com
```

En OpenSSH es posible configurar estos algoritmos modificando la opción `MACs` alojada en el archivo `/etc/ssh/sshd_config`.

## Referencias

- https://datatracker.ietf.org/doc/html/rfc2104/
- https://datatracker.ietf.org/doc/html/rfc6668/
- https://cwe.mitre.org/data/definitions/327.html
- https://capec.mitre.org/data/definitions/217.html
- https://attack.mitre.org/techniques/T1557/