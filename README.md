# Encriptador

Protege archivos con una clave. Funciona en el navegador, sin internet, y nada sale de tu equipo.

**Abrir la app:** https://calidad-lgtm.github.io/encriptador/

- **Proteger:** elige un archivo, usa la clave generada y descarga el archivo `.protegido.html`. Ese archivo trae las instrucciones y se abre con doble clic.
- **Abrir:** escribe la clave en el archivo protegido, o cárgalo en la pestaña *Abrir* de la app.
- **Recuperación:** cada archivo también se abre con el código de recuperación de quien lo protegió (Configuración en la app).
- **Instalar:** botón *Instalar* en Chrome/Edge, *Archivo → Añadir al Dock* en Safari, o *Compartir → Añadir a inicio* en iPhone.

Cifrado AES-256-GCM con claves derivadas por PBKDF2-SHA256 (250.000 iteraciones), usando la Web Crypto API del navegador.
