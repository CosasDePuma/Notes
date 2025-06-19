---
tags:
  - hacking
  - vulnerabilities
  - ssh
---

|            | Información                                                         |
| ---------- | ------------------------------------------------------------------- |
| **Riesgo** | Bajo (2.9)                                                          |
| **CVSS**   | CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N/E:P |

## Descripción

Se ha detectado que uno o más servicios SSH ofrecen autenticación basada en contraseña.

La autenticación por contraseña en SSH es considerada un método de autenticación débil comparado con alternativas más robustas como la autenticación por clave pública, incluso si el servicio no se encuentra expuesto públicamente.

El protocolo SSH soporta varios métodos de autenticación, cada uno con un enfoque de seguridad diferente. Algunos de estos métodos son:

- Basado en contraseña (`password`), donde el usuario proporciona su nombre de usuario y contraseña.
- Basado en claves públicas (`publickey`), el cual utiliza un par de claves criptográficas (pública y privada).
- Basada en el host (`hostbased`), donde la autenticación ocurre comprobando la identidad del cliente, mediante una lista blanca de hosts conocidos.
- Basado en respuestas de teclado interactivo (`keyboard-interactive`), comúnmente usado para implementar autenticación multi-factor (MFA) o integración con sistemas como PAM.

## Impacto

Un actor malicioso podría realizar ataques automatizados de fuerza bruta o _guessing_ contra el servicio SSH aprovechando la autenticación por contraseña.

Es importante destacar que este escenario de ataque depende de otros factores, como la ausencia de medidas para prevenir fuerza bruta, políticas de contraseñas robustas o restricciones de acceso.

## Evidencias

Para verificar cuales eran los métodos de autenticación ofrecidos, se ejecutó el siguiente comando:

```sh
nmap --script ssh-auth-methods -p [puerto] [host]
```

==EVIDENCIAS==

## Mitigaciones

Se recomienda configurar el servidor SSH para deshabilitar la autenticación basada en contraseñas.

En OpenSSH y similares, es posible configurar estos algoritmos modificando la opción `PasswordAuthentication` alojada en el archivo `/etc/ssh/sshd_config`.

```
PasswordAuthentication no
```

## Referencias

- https://datatracker.ietf.org/doc/html/rfc4252#section-8
- [https://capec.mitre.org/data/definitions/49.html](https://capec.mitre.org/data/definitions/49.html)
- [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)