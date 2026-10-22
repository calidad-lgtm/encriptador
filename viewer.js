// Pantalla del archivo protegido (.html). Se copia dentro de cada archivo, después de core.js.
// El archivo lleva una política CSP que le impide conectarse a internet: la clave nunca puede salir del equipo.
(() => {
  const $ = id => document.getElementById(id);
  const key = $("key"), run = $("run"), eye = $("eye");
  const setMsg = (t, cls = "") => { $("msg").textContent = t; $("msg").className = "msg " + cls; };
  let data;
  try { data = b64dec($("payload").textContent); }
  catch { return setMsg("El archivo está dañado o fue modificado. No es seguro usarlo.", "err"); }

  key.oninput = () => run.disabled = !key.value.trim();
  key.onkeydown = e => { if (e.key === "Enter" && !run.disabled) run.click(); };
  eye.onclick = () => {
    const show = key.type === "password";
    key.type = show ? "text" : "password";
    eye.querySelector("span").textContent = show ? "Ocultar" : "Mostrar";
  };
  run.onclick = async () => {
    if (!window.crypto?.subtle)
      return setMsg("Este navegador bloquea el descifrado aquí. Guarda el archivo en tu computador y ábrelo con doble clic (Chrome, Edge, Safari o Firefox).", "err");
    run.disabled = true;
    setMsg("Abriendo…");
    try {
      const { name, bytes } = await decrypt(data, key.value);
      download(bytes, name);
      key.value = ""; key.type = "password"; eye.querySelector("span").textContent = "Mostrar";
      setMsg(`Listo. Se descargó "${name}". Búscalo en tu carpeta de Descargas.` +
        (/\.zip$/i.test(name) ? " Es una carpeta comprimida: ábrela con doble clic." : ""), "ok");
    } catch (e) {
      setMsg(e.message || "Ocurrió un error.", "err");
    } finally { run.disabled = !key.value.trim(); }
  };
})();
