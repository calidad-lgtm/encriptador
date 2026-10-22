# Encriptador

Protege archivos con una clave. Funciona en el navegador, sin internet, y nada sale de tu equipo.

**Abrir la app:** https://calidad-lgtm.github.io/encriptador/

- **Proteger:** elige un archivo, usa la clave generada y descarga el archivo `.protegido.html`. Ese archivo trae las instrucciones y se abre con doble clic.
- **Abrir:** escribe la clave en el archivo protegido, o cárgalo en la pestaña *Abrir* de la app.
- **Recuperación:** si se pierde la clave, el área de Calidad puede recuperar el archivo con la llave maestra de la oficina.
- **Instalar:** botón *Instalar* en Chrome/Edge, *Archivo → Añadir al Dock* en Safari, o *Compartir → Añadir a inicio* en iPhone.

Cifrado AES-256-GCM con claves derivadas por PBKDF2-SHA256 (250.000 iteraciones), usando la Web Crypto API del navegador.

## Llave maestra

Cada archivo guarda su llave cifrada dos veces: con la clave del archivo y con la **llave maestra pública** (`llave-publica.json`, RSA-OAEP 3072). La parte pública solo protege; no puede abrir nada.

La **llave privada** se crea con `node herramientas/crear-llave-maestra.mjs`, queda cifrada con contraseña en `llave-maestra/` y **nunca se sube a GitHub** (está en `.gitignore`). Para recuperar un archivo: abrir la app con `?maestra`.
