# Encriptador

Protege archivos con una clave. Funciona en el navegador, sin internet, y nada sale de tu equipo.

**Abrir la app:** https://calidad-lgtm.github.io/encriptador/

- **Proteger:** elige un archivo, usa la clave generada y descarga el archivo `.protegido.html`. Ese archivo trae las instrucciones y se abre con doble clic.
- **Abrir:** escribe la clave en el archivo protegido, o cárgalo en la pestaña *Abrir* de la app.
- **Recuperación:** si se pierde la clave, el área de Calidad puede recuperar el archivo con la llave maestra de la oficina.
- **Instalar:** botón *Instalar* en Chrome/Edge, *Archivo → Añadir al Dock* en Safari, o *Compartir → Añadir a inicio* en iPhone.

## Seguridad

- **Cifrado:** AES-256-GCM con una llave aleatoria por archivo. La clave se refuerza con PBKDF2-SHA-256 (1.000.000 de iteraciones, guardadas en el archivo para poder subirlas en el futuro).
- **Formato ENC5:** toda la cabecera está autenticada (AAD). Si se cambia un solo byte del archivo, se rechaza.
- **Claves:** las generadas tienen unos 139 bits. Las propias deben tener al menos 16 caracteres y no pueden ser predecibles.
- **Metadatos:** el nombre del documento va cifrado (y oculto por defecto) y el tamaño se disimula con relleno PADMÉ.
- **Archivo `.html`:** su política CSP le impide cualquier conexión a internet. **Archivo `.enc`:** no lleva código, solo se abre en la app oficial (opción más segura).
- **App:** CSP estricta sin scripts incrustados, no funciona dentro de otras páginas y no envía datos a ningún servidor.

## Llave maestra

Cada archivo guarda su llave y su clave selladas con la **llave maestra pública** (`llave-publica.json`, RSA-OAEP 3072). La parte pública solo protege; no puede abrir nada.

La **llave privada** se crea con `node herramientas/crear-llave-maestra.mjs`, queda cifrada con contraseña en `llave-maestra/` y **nunca se sube a GitHub** (está en `.gitignore`). Para recuperar un archivo o ver su clave: abrir la app con `?maestra`. La ventana se bloquea sola tras 5 minutos sin uso.
