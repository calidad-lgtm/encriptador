// Interfaz del Encriptador. El cifrado está en core.js; la pantalla de los archivos protegidos, en viewer.js.
"use strict";

// No funcionar dentro de otra página (evita que un sitio falso la incruste para engañar clics)
if (window.top !== window.self) {
  document.body.textContent = "Por seguridad, el Encriptador solo funciona abierto directamente.";
  throw new Error("La app no puede abrirse dentro de otra página.");
}

const $ = id => document.getElementById(id);

// --- Íconos ---
const PATHS = {
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  unlock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.7"/>',
  upload: '<path d="M12 15V4M7 9l5-5 5 5"/><path d="M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5"/><path d="M5 20h14"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.4-5.7L20 8.6"/><path d="M20 3v5.6h-5.6"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M16 7l3 3M14 9l2 2"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.2a2.5 2.5 0 1 1 3.4 2.4c-.6.3-1 .8-1 1.5v.4"/><path d="M12 17h.01"/>',
  check: '<path d="M5 12.5 9.5 17 19 7.5"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  shield: '<path d="M12 3 20 6v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  offline: '<path d="M2 9a15 15 0 0 1 20 0M5.5 12.5a10 10 0 0 1 13 0M9 16a5 5 0 0 1 6 0"/><path d="M12 20h.01"/>',
  spinner: '<path d="M12 3a9 9 0 1 0 9 9"/>',
};
const I = (name, cls = "") => `<svg viewBox="0 0 24 24" aria-hidden="true" class="${cls}">${PATHS[name]}</svg>`;
document.querySelectorAll("[data-i]").forEach(el => el.insertAdjacentHTML("afterbegin", I(el.dataset.i)));

// --- Almacenamiento local (puede fallar en ventanas privadas) ---
const store = {
  get: k => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch {} },
  del: k => { try { localStorage.removeItem(k); } catch {} },
};

// Llave maestra PÚBLICA (de llave-publica.json). Solo sirve para proteger, no para abrir.
// La llave privada que abre los archivos queda fuera de GitHub, en llave-maestra/.
const MASTER_PUB = {"id":"246cf9cca49a5d7c","spki":"MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA56Wt0N7CZ7+bkgmzLkRP6/9ompg68Zr+wWWzBkmTDRqcs1hxoxO2XYeMtqECV0nEXpn1w8CIOPvSnk8Pm2xR73a2p//u8QTRBj2EVItO64PbesE8VnBI/sZDaGBnax9bk72LJ26r0oJmdzm29jwHB/oLtERo8y1pgmjHhtFCzNV+2xtbW/XQYzOedbzxl4kW4SzHdwYP8L8b3UaP2D9JVC6K/SvIM+cGpr5XPNgUKHMHSxunBboyiVGHkqTusaXVsAvuFGnZ+PBb9+SsqCBCSUx83lFmmFytHx75CB1I3dK/W+zPprI6worzrndf30TijnlCLKnZ0Ydt+hPTOu4b65aXN+V3jw4CCeRd2cUiO7R5YAEku1V6jIOf+VV0HqImMbetYZNcQkityCAYGhxvhQKaDYsxtMqov2mCN6o3MHQEZAKyEkjoxb0We9dkvqyflZIVeb4WqCXrp9S5RG40RV1GX5/eW2CeN4a2Bhteh4FjncpZUVzMjwYCva4GQaYJAgMBAAE="};
const hexToBytes = h => Uint8Array.from(h.match(/../g), x => parseInt(x, 16));
let masterPub = null;
async function getMasterPub() {
  return masterPub ??= {
    id: hexToBytes(MASTER_PUB.id),
    key: await crypto.subtle.importKey("spki", b64dec(MASTER_PUB.spki), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]),
  };
}

// Código que se copia dentro de cada archivo protegido (.html)
const embedded = Promise.all(["core.js", "viewer.js"].map(f =>
  fetch(f).then(r => { if (!r.ok) throw new Error(); return r.text(); })));

// sel: lo elegido. single = un archivo; entries = varios o una carpeta (se comprimen en .zip)
let mode = "enc", sel = null, last = null;

// --- Modo Proteger / Abrir ---
const TEXT = {
  enc: { file: "Elige archivos o una carpeta", key: "Clave para abrirlo", run: "Proteger y descargar", placeholder: "Escribe una clave o pulsa «Nueva»" },
  dec: { file: "Elige el archivo protegido", key: "Escribe la clave", run: "Abrir y descargar", placeholder: "Clave del archivo" },
};
function setMode(m) {
  mode = m;
  document.querySelectorAll(".seg button").forEach(b => b.setAttribute("aria-selected", b.dataset.mode === m));
  const t = TEXT[m];
  $("fileTitle").textContent = t.file;
  $("keyTitle").textContent = t.key;
  $("key").placeholder = t.placeholder;
  $("key").type = m === "enc" ? "text" : "password";
  $("file").accept = m === "dec" ? ".html,.htm,.enc" : "";
  $("file").multiple = m === "enc";
  $("pickFiles").textContent = m === "enc" ? "Elegir archivos" : "Elegir archivo";
  $("pickFolder").hidden = m === "dec" || !("webkitdirectory" in $("folder"));
  $("gen").hidden = $("copy").hidden = $("meter").hidden = $("opts").hidden = m === "dec";
  $("eye").hidden = m === "enc";
  $("key").value = m === "enc" ? generateKey() : "";
  setEye(false);
  setFile(null);
  $("result").hidden = true; $("form").hidden = false;
}
document.querySelectorAll(".seg button").forEach(b => b.onclick = () => setMode(b.dataset.mode));

// --- Archivo ---
function makeDrop(dropEl, inputEl, onFile) {
  inputEl.onchange = e => onFile(e.target.files[0]);
  dropEl.ondragover = e => { e.preventDefault(); dropEl.classList.add("over"); };
  dropEl.ondragleave = () => dropEl.classList.remove("over");
  dropEl.ondrop = e => { e.preventDefault(); dropEl.classList.remove("over"); onFile(e.dataTransfer.files[0]); };
}
function showFile(dropEl, textEl, f, emptyHtml) {
  dropEl.classList.toggle("has-file", !!f);
  if (!f) return textEl.innerHTML = emptyHtml;
  textEl.innerHTML = "<strong></strong><br><small></small>";
  textEl.querySelector("strong").textContent = f.name;
  textEl.querySelector("small").textContent = `${fmtSize(f.size)} · haz clic para cambiarlo`;
}

// Archivos de sistema que no vale la pena incluir
const JUNK = /^(\.DS_Store|Thumbs\.db|desktop\.ini|\._.*)$/i;

// entries: [{ path: "Carpeta/sub/a.pdf", file }]
function setSelection(entries) {
  entries = (entries || []).filter(e => !JUNK.test(e.path.split("/").pop()));
  $("file").value = $("folder").value = "";
  sel = null;
  if (entries.length === 1 && !entries[0].path.includes("/")) {
    const f = entries[0].file;
    sel = { single: f, name: f.name, size: f.size, count: 1 };
  } else if (entries.length) {
    const tops = new Set(entries.map(e => e.path.split("/")[0]));
    const folder = tops.size === 1 && entries[0].path.includes("/") ? [...tops][0] : null;
    sel = { entries, folder, name: (folder || "Archivos") + ".zip", count: entries.length,
      size: entries.reduce((s, e) => s + e.file.size, 0) };
  }
  renderSelection();
  if (mode === "dec" && sel && !sel.single) { sel = null; renderSelection(); setMsg("En Abrir, elige un solo archivo protegido.", "err"); }
  else if (sel && sel.size > 300 * 1024 * 1024) setMsg("Es bastante grande (" + fmtSize(sel.size) + "): puede tardar o fallar en equipos con poca memoria.");
  else setMsg("");
  refresh();
}
function renderSelection() {
  const d = $("drop"), t = $("dropText");
  d.classList.toggle("has-file", !!sel);
  if (!sel) return t.innerHTML = mode === "enc"
    ? "<strong>Arrastra archivos o una carpeta aquí</strong><br><small>Varios archivos o carpetas se guardan juntos en un .zip</small>"
    : "<strong>Arrastra el archivo protegido aquí</strong><br><small>.html o .enc</small>";
  t.innerHTML = "<strong></strong><br><small></small>";
  t.querySelector("strong").textContent = sel.single ? sel.name : (sel.folder || `${sel.count} archivos`);
  t.querySelector("small").textContent = sel.single ? fmtSize(sel.size)
    : `${sel.folder ? "Carpeta" : "Archivos"} · ${sel.count} archivo${sel.count === 1 ? "" : "s"} · ${fmtSize(sel.size)} · se guardará como ${sel.name}`;
}
function setFile(f) { setSelection(f ? [{ path: f.name, file: f }] : []); }

// Lee una carpeta soltada (con subcarpetas)
async function readEntry(entry, prefix = "") {
  if (entry.isFile) return [{ path: prefix + entry.name, file: await new Promise((ok, ko) => entry.file(ok, ko)) }];
  const reader = entry.createReader(), out = [];
  for (;;) {
    const batch = await new Promise((ok, ko) => reader.readEntries(ok, ko));
    if (!batch.length) return out;
    for (const e of batch) out.push(...await readEntry(e, prefix + entry.name + "/"));
  }
}

const dropZone = $("drop");
const pickFiles = list => setSelection([...list].map(f => ({ path: f.webkitRelativePath || f.name, file: f })));
$("file").onchange = e => pickFiles(e.target.files);
$("folder").onchange = e => pickFiles(e.target.files);
$("pickFiles").onclick = () => $("file").click();
$("pickFolder").onclick = () => $("folder").click();
dropZone.onclick = e => { if (!e.target.closest("button, input")) $("file").click(); };
dropZone.ondragover = e => { e.preventDefault(); dropZone.classList.add("over"); };
dropZone.ondragleave = () => dropZone.classList.remove("over");
dropZone.ondrop = async e => {
  e.preventDefault(); dropZone.classList.remove("over");
  // webkitGetAsEntry debe llamarse antes de cualquier await
  const roots = [...e.dataTransfer.items].map(i => i.webkitGetAsEntry?.()).filter(Boolean);
  const files = [...e.dataTransfer.files];
  try {
    setSelection(roots.length ? (await Promise.all(roots.map(r => readEntry(r)))).flat() : files.map(f => ({ path: f.name, file: f })));
  } catch { setMsg("No se pudo leer lo que soltaste. Prueba con «Elegir carpeta».", "err"); }
};

// --- Clave ---
// Una clave propia debe resistir ataques de fuerza bruta sin conexión: largo mínimo, sin patrones conocidos.
const WEAK = /(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf|zxcv|pass|contrase|clave|calidad|auditor|admin|qwerty)/i;
function keyStrength(raw) {
  const k = clean(raw);
  if (!k) return { ok: false, bits: 0, msg: "" };
  let pool = 0;
  if (/[a-z]/.test(k)) pool += 26;
  if (/[A-Z]/.test(k)) pool += 26;
  if (/\d/.test(k)) pool += 10;
  if (/[^A-Za-z0-9]/.test(k)) pool += 33;
  const distinct = new Set(k).size;
  let bits = Math.round(k.length * Math.log2(pool) * Math.min(1, distinct / 10));
  if (WEAK.test(k) || /(.)\1{3,}/.test(k)) bits = Math.min(bits, 30);
  if (k.length < 16) return { ok: false, bits, msg: `Muy corta: usa al menos 16 caracteres (lleva ${k.length}) o pulsa «Nueva».` };
  if (bits < 75) return { ok: false, bits, msg: "Muy predecible: evita palabras comunes y secuencias, mezcla letras, números y símbolos, o pulsa «Nueva»." };
  return { ok: true, bits, msg: bits >= 120 ? "Clave muy fuerte. Compártela por otro medio (teléfono o WhatsApp), nunca en el mismo correo." : "Clave fuerte. Compártela por otro medio, nunca en el mismo correo." };
}
function renderStrength() {
  if (mode !== "enc") return;
  const s = keyStrength($("key").value);
  const pct = Math.min(100, Math.round(s.bits / 128 * 100));
  $("meterBar").style.width = pct + "%";
  $("meter").className = "meter " + (s.ok ? (s.bits >= 120 ? "great" : "good") : s.bits ? "weak" : "");
  $("keyHint").textContent = s.msg || "Usa la clave generada o escribe una de al menos 16 caracteres.";
  $("keyHint").className = "hint" + (s.ok || !s.bits ? "" : " bad");
}
function setEye(show) {
  if (mode === "dec") $("key").type = show ? "text" : "password";
  $("eye").querySelector("span").textContent = show ? "Ocultar" : "Mostrar";
}
$("eye").onclick = () => setEye($("key").type === "password");
$("key").oninput = refresh;
$("key").onkeydown = e => { if (e.key === "Enter" && !$("run").disabled) $("run").click(); };
$("gen").onclick = () => { $("key").value = generateKey(); refresh(); };
$("copy").onclick = e => copyText($("key").value, e.currentTarget);
$("copyResult").onclick = e => last && copyText(last.key, e.currentTarget);

async function copyText(text, btn) {
  if (!text) return;
  const label = btn.querySelector("span"), old = label.textContent;
  try { await navigator.clipboard.writeText(text); label.textContent = "Copiada"; }
  catch { label.textContent = "No se pudo"; }
  setTimeout(() => label.textContent = old, 1500);
}

function refresh() {
  if (mode === "enc") renderStrength();
  else $("keyHint").textContent = "Acepta archivos .html protegidos y .enc.";
  const keyOk = mode === "enc" ? keyStrength($("key").value).ok : !!clean($("key").value);
  $("run").disabled = !sel || !keyOk;
}
function setMsg(t, cls = "", el = $("msg")) { el.textContent = t; el.className = "msg " + cls; }
function setBusy(on) {
  const b = $("run");
  if (on) { b.dataset.busy = "1"; b.disabled = true; busyText("Procesando…"); }
  else { delete b.dataset.busy; b.textContent = TEXT[mode].run; refresh(); }
}
function busyText(t) { $("run").innerHTML = I("spinner", "spin") + t; }

// --- Acción principal ---
$("run").onclick = async () => {
  if (!window.crypto?.subtle)
    return setMsg("Tu navegador bloquea el cifrado aquí. Abre la app desde https o instalada.", "err");
  setBusy(true); setMsg("");
  try {
    if (mode === "enc") {
      const key = clean($("key").value);
      if (!keyStrength(key).ok) throw new Error("La clave no es suficientemente segura.");
      const data = sel.single ? new Uint8Array(await sel.single.arrayBuffer())
        : await makeZip(sel.entries, (i, n) => busyText(`Comprimiendo ${i} de ${n}…`));
      busyText("Protegiendo…");
      const hide = $("optHideName").checked, asEnc = $("optEnc").checked;
      const out = await encrypt(data, sel.name, key, await getMasterPub());
      data.fill(0);
      const base = hide ? `archivo-protegido-${new Date().toISOString().slice(0, 10)}-${[...rand(3)].map(b => b.toString(16).padStart(2, "0")).join("")}` : sel.name;
      const outName = base + (asEnc ? ".enc" : hide ? ".html" : ".protegido.html");
      if (asEnc) download(out, outName);
      else download(enc(await buildProtectedPage(hide ? null : sel.name, out)), outName, "text/html");
      last = { key, name: sel.name, outName, asEnc };
      await addHistory(sel.name, outName, key);
      $("resultName").textContent = "Se descargó " + outName;
      $("resultSend").textContent = asEnc
        ? "Envía el archivo .enc. Quien lo reciba lo abre en esta app, pestaña Abrir."
        : "Envía el archivo. Ya incluye las instrucciones para abrirlo.";
      $("form").hidden = true; $("result").hidden = false;
    } else {
      const data = new Uint8Array(await sel.single.arrayBuffer());
      const { name, bytes } = await decrypt(extractPayload(data), $("key").value);
      download(bytes, name);
      $("key").value = ""; setEye(false);
      setMsg(`Listo. Se descargó "${name}".` + (/\.zip$/i.test(name) ? " Ábrelo con doble clic para ver la carpeta." : ""), "ok");
    }
  } catch (e) {
    setMsg(e.message || "Ocurrió un error.", "err");
  } finally { setBusy(false); }
};
$("againBtn").onclick = () => { last = null; setMode("enc"); };
$("guideBtn").onclick = () => last && download(enc(buildGuide(last)), last.outName + ".INSTRUCTIVO.txt");
$("keyTxtBtn").onclick = () => last && download(enc(
  `CLAVE — Archivo protegido\r\n\r\n` +
  `Archivo:  ${last.outName}\r\n` +
  `Fecha:    ${new Date().toLocaleString("es-CL")}\r\n\r\n` +
  `Clave:    ${last.key}\r\n\r\n` +
  `Guarda este documento en un lugar seguro y SEPARADO del archivo protegido.\r\n` +
  `No lo envíes en el mismo correo: quien tenga esta clave puede abrir el archivo.\r\n`), last.outName + ".CLAVE.txt");

// --- ZIP (para carpetas y varios archivos). Se abre con doble clic en Mac y Windows. ---
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
function crc32(d) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < d.length; i++) c = CRC_TABLE[(c ^ d[i]) & 255] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}
async function deflate(data) {
  if (typeof CompressionStream === "undefined") return null;
  try { return new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer()); }
  catch { return null; }
}
async function makeZip(entries, onProgress) {
  if (entries.length > 65535) throw new Error("Son demasiados archivos (máximo 65.535).");
  const parts = [], central = [];
  let offset = 0;
  for (const [i, { path, file }] of entries.entries()) {
    onProgress?.(i + 1, entries.length);
    const data = new Uint8Array(await file.arrayBuffer());
    const name = enc(path), crc = crc32(data);
    let body = await deflate(data), method = 8;           // 8 = comprimido
    if (!body || body.length >= data.length) { body = data; method = 0; } // 0 = sin comprimir
    const d = new Date(file.lastModified || Date.now());
    const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
    const date = ((Math.max(d.getFullYear(), 1980) - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    const h = new DataView(new ArrayBuffer(30));
    h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(6, 0x0800, true); h.setUint16(8, method, true);
    h.setUint16(10, time, true); h.setUint16(12, date, true); h.setUint32(14, crc, true);
    h.setUint32(18, body.length, true); h.setUint32(22, data.length, true); h.setUint16(26, name.length, true);
    const c = new DataView(new ArrayBuffer(46));
    c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(8, 0x0800, true);
    c.setUint16(10, method, true); c.setUint16(12, time, true); c.setUint16(14, date, true); c.setUint32(16, crc, true);
    c.setUint32(20, body.length, true); c.setUint32(24, data.length, true); c.setUint16(28, name.length, true);
    c.setUint32(42, offset, true);
    parts.push(new Uint8Array(h.buffer), name, body);
    central.push(new Uint8Array(c.buffer), name);
    offset += 30 + name.length + body.length;
    if (offset > 0xFFFFFFFF) throw new Error("La carpeta supera los 4 GB; divídela en partes.");
  }
  const cdSize = central.reduce((s, p) => s + p.length, 0);
  const e = new DataView(new ArrayBuffer(22));
  e.setUint32(0, 0x06054b50, true); e.setUint16(8, entries.length, true); e.setUint16(10, entries.length, true);
  e.setUint32(12, cdSize, true); e.setUint32(16, offset, true);
  return concat(...parts, ...central, new Uint8Array(e.buffer));
}

// Acepta un archivo protegido (.html) o un .enc. Nunca ejecuta el código del .html: solo extrae los datos cifrados.
function extractPayload(data) {
  if (data[0] === 0x3c) { // "<"
    const m = new TextDecoder().decode(data).match(/<script id="payload"[^>]*>([A-Za-z0-9+/=\s]*)<\/script>/);
    if (m) return b64dec(m[1]);
    throw new Error("Este archivo no fue creado con este encriptador.");
  }
  return data;
}

// --- Recuperación maestra (oculta: solo con ?maestra o si este navegador ya guardó la llave) ---
const MK_STORE = "encriptador.llaveMaestra", HIST_STORE = "encriptador.historial";
const HIST_LABEL = enc("encriptador/historial");
const AUTO_LOCK_MS = 5 * 60 * 1000;
let mkJson = store.get(MK_STORE), mkFileJson = null, mfFile = null, unlocked = null, lockTimer = 0;

function renderMaster() {
  $("masterBtn").hidden = !(mkJson || new URLSearchParams(location.search).has("maestra"));
  $("mkLock").hidden = !!unlocked;
  $("mkOpen").hidden = !unlocked;
  $("mkLoaded").hidden = !mkJson;
  $("mkPick").hidden = !!mkJson;
  $("mkUnlock").disabled = !(mkJson || mkFileJson) || !$("mkPw").value;
  $("mkRun").disabled = !mfFile;
}
makeDrop($("mkDrop"), $("mkFile"), async f => {
  mkFileJson = null;
  showFile($("mkDrop"), $("mkText"), f, "<strong>Elige llave-maestra.privada.json</strong>");
  try {
    const text = await f.text();
    if (JSON.parse(text).tipo !== "encriptador-llave-maestra") throw 0;
    mkFileJson = text; setMsg("", "", $("mkMsg"));
  } catch { setMsg("Ese archivo no es una llave maestra del Encriptador.", "err", $("mkMsg")); }
  renderMaster();
});
makeDrop($("mfDrop"), $("mfFile"), f => {
  mfFile = f || null;
  showFile($("mfDrop"), $("mfText"), mfFile, "<strong>Elige el archivo protegido</strong>");
  $("mkKeyBox").hidden = true;
  setMsg("", "", $("mkMsg")); renderMaster();
});
$("mkPw").oninput = renderMaster;
$("mkPw").onkeydown = e => { if (e.key === "Enter" && !$("mkUnlock").disabled) $("mkUnlock").click(); };
$("mkForget").onclick = () => { store.del(MK_STORE); mkJson = null; renderMaster(); };

// Descifra la llave privada con la contraseña. La llave queda en memoria como no exportable y nunca se guarda descifrada.
async function unlockMaster(json, pw) {
  const k = JSON.parse(json);
  const iters = k.kdf.iteraciones;
  if (!(iters >= MIN_ITER && iters <= MAX_ITER)) throw new Error("La llave maestra está dañada.");
  const kek = await deriveKey(pw, b64dec(k.kdf.salt), iters);
  let pkcs8;
  try { pkcs8 = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64dec(k.iv) }, kek, b64dec(k.datos))); }
  catch { throw new Error("La contraseña de la llave maestra no es correcta."); }
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  pkcs8.fill(0);
  return { id: hexToBytes(k.id), key };
}

$("mkUnlock").onclick = async () => {
  const b = $("mkUnlock");
  b.disabled = true; b.innerHTML = I("spinner", "spin") + "Desbloqueando…";
  setMsg("", "", $("mkMsg"));
  try {
    const json = mkJson || mkFileJson;
    unlocked = await unlockMaster(json, $("mkPw").value);
    $("mkPw").value = "";
    if (!mkJson && $("mkRemember").checked) { store.set(MK_STORE, json); mkJson = json; }
    touchMaster();
    await renderHistory();
  } catch (e) {
    setMsg(e.message || "Ocurrió un error.", "err", $("mkMsg"));
  } finally {
    b.innerHTML = I("unlock") + "Desbloquear"; renderMaster();
  }
};

// Al bloquear se olvida todo lo descifrado
function lockMaster() {
  clearTimeout(lockTimer);
  unlocked = null; mfFile = null;
  $("mkPw").value = ""; $("hist").textContent = ""; $("mkKey").textContent = ""; $("mkKeyBox").hidden = true;
  showFile($("mfDrop"), $("mfText"), null, "<strong>Elige el archivo protegido</strong>");
  setMsg("", "", $("mkMsg")); renderMaster();
}
// Se bloquea sola tras 5 minutos sin uso
function touchMaster() {
  if (!unlocked) return;
  clearTimeout(lockTimer);
  lockTimer = setTimeout(() => { lockMaster(); setMsg("Se bloqueó por inactividad.", "", $("mkMsg")); }, AUTO_LOCK_MS);
}
["pointerdown", "keydown"].forEach(ev => $("master").addEventListener(ev, touchMaster));
$("mkLockBtn").onclick = lockMaster;

$("mkRun").onclick = async () => {
  const b = $("mkRun");
  b.disabled = true; b.innerHTML = I("spinner", "spin") + "Recuperando…";
  setMsg("", "", $("mkMsg")); $("mkKeyBox").hidden = true;
  try {
    const { name, bytes, key } = await decryptMaster(extractPayload(new Uint8Array(await mfFile.arrayBuffer())), unlocked);
    download(bytes, name);
    $("mkKey").textContent = key || "";
    $("mkKeyBox").hidden = !key;
    setMsg(`Listo. Se descargó "${name}".` + (key ? "" : " Su clave no quedó guardada (archivo de una versión anterior)."), "ok", $("mkMsg"));
  } catch (e) {
    setMsg(e.message || "Ocurrió un error.", "err", $("mkMsg"));
  } finally {
    b.textContent = "Recuperar y ver clave"; renderMaster();
  }
};
$("mkKeyCopy").onclick = e => copyText($("mkKey").textContent, e.currentTarget);

// --- Historial de claves: cada entrada va sellada con la llave maestra pública; solo Calidad puede leerlo ---
function loadHist() { try { return JSON.parse(store.get(HIST_STORE) || "[]"); } catch { return []; } }
async function addHistory(name, outName, key) {
  try {
    let plain = enc(JSON.stringify({ n: name.slice(0, 80), o: outName.slice(0, 60), k: key }));
    if (plain.length > RSA_MAX) plain = enc(JSON.stringify({ n: name.slice(0, 40), k: key }));
    if (plain.length > RSA_MAX) return;
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP", label: HIST_LABEL }, (await getMasterPub()).key, plain));
    const h = loadHist();
    h.unshift({ t: new Date().toISOString(), s: b64enc(sealed) });
    store.set(HIST_STORE, JSON.stringify(h.slice(0, 500)));
  } catch {}
}
async function openHistEntry(s) {
  const data = b64dec(s);
  for (const params of [{ name: "RSA-OAEP", label: HIST_LABEL }, { name: "RSA-OAEP" }]) { // con y sin etiqueta (entradas antiguas)
    try { return JSON.parse(toText(await crypto.subtle.decrypt(params, unlocked.key, data))); } catch {}
  }
  return null;
}
async function renderHistory() {
  const ul = $("hist"), items = loadHist();
  ul.textContent = "";
  if (!items.length) return ul.innerHTML = '<li class="empty">Aún no hay archivos protegidos en este equipo.</li>';
  for (const it of items) {
    const r = await openHistEntry(it.s);
    const li = document.createElement("li");
    li.innerHTML = "<div><b></b><code></code><br><small></small></div>";
    li.querySelector("b").textContent = r ? r.n : "(protegido con otra llave maestra)";
    li.querySelector("code").textContent = r ? r.k : "";
    li.querySelector("small").textContent = new Date(it.t).toLocaleString("es-CL") + (r?.o ? " · " + r.o : "");
    if (r?.k) {
      const btn = document.createElement("button");
      btn.className = "btn btn-sm"; btn.type = "button";
      btn.innerHTML = I("copy") + "<span>Copiar</span>";
      btn.onclick = () => copyText(r.k, btn);
      li.append(btn);
    }
    ul.append(li);
  }
}
$("histClear").onclick = () => {
  if (!confirm("¿Borrar el historial de claves de este equipo?")) return;
  store.del(HIST_STORE);
  renderHistory();
};

// --- Diálogos ---
$("masterBtn").onclick = () => { renderMaster(); $("master").showModal(); };
$("helpBtn").onclick = () => $("help").showModal();
document.querySelectorAll("dialog").forEach(d => {
  d.onclick = e => { if (e.target === d || e.target.closest("[data-close]")) d.close(); };
});
$("master").addEventListener("close", lockMaster);

// --- Instalación (PWA) ---
let installEvent = null;
addEventListener("beforeinstallprompt", e => { e.preventDefault(); installEvent = e; $("installBtn").hidden = false; });
addEventListener("appinstalled", () => { installEvent = null; $("installBtn").hidden = true; });
$("installBtn").onclick = async () => {
  if (!installEvent) return $("help").showModal();
  installEvent.prompt();
  await installEvent.userChoice;
  installEvent = null; $("installBtn").hidden = true;
};
if ("serviceWorker" in navigator && (location.protocol === "https:" || location.hostname === "localhost"))
  navigator.serviceWorker.register("sw.js").catch(() => {});

// --- Textos y archivos generados ---
const esc = s => s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const fmtSize = n => n < 1024 * 1024 ? (n / 1024).toFixed(1) + " KB" : (n / 1024 / 1024).toFixed(1) + " MB";
const OFFICIAL_URL = "https://calidad-lgtm.github.io/encriptador/";

// Archivo .html autocontenido. Su CSP bloquea toda conexión: el código no puede enviar la clave a ningún lado.
// name = null oculta el nombre del documento (solo se ve al abrirlo con la clave).
async function buildProtectedPage(name, bytes) {
  const [coreSrc, viewerSrc] = await embedded.catch(() => { throw new Error("No se pudo preparar el archivo. Recarga la app con internet e inténtalo de nuevo."); });
  const code = (coreSrc + "\n" + viewerSrc).replace(/<\/(script)/gi, "<\\/$1");
  const n = name ? esc(name) : null;
  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Archivo protegido</title>
<style>${$("styles").textContent}</style>
</head>
<body>
<div class="app">
  <header class="topbar">
    <div class="brand">
      <span class="logo">${I("lock")}</span>
      <div><b>Archivo protegido</b><small>${n ?? "Cifrado con AES-256"}</small></div>
    </div>
  </header>
  <section class="panel">
    <div class="step"><span class="num">${I("help")}</span><h2>Cómo abrirlo</h2></div>
    <ol class="steps">
      <li>Escribe la clave que te entregaron (por teléfono, WhatsApp u otro medio).</li>
      <li>Pulsa <strong>Abrir archivo</strong>.</li>
      <li>Se descargará ${n ? `<strong>${n}</strong>` : "el documento original"}, listo para abrir. Búscalo en tu carpeta de Descargas.</li>${/\.zip$/i.test(name || "") ? `
      <li>Es una carpeta comprimida: ábrela con doble clic para ver su contenido.</li>` : ""}
    </ol>
    <div class="step"><span class="num">${I("key")}</span><h2>Clave</h2></div>
    <div class="input-wrap">
      <input type="password" id="key" autocomplete="off" spellcheck="false" placeholder="Escribe la clave" aria-label="Clave" autofocus>
      <button class="btn btn-sm" id="eye" type="button">${I("eye")}<span>Mostrar</span></button>
    </div>
    <button class="btn btn-primary btn-block" id="run" disabled>${I("unlock")}Abrir archivo</button>
    <div class="msg" id="msg" role="status"></div>
    <p class="warn"><strong>Importante:</strong> si olvidas la clave, el archivo no se podrá abrir. Pide a quien te lo envió que lo vuelva a enviar.</p>
    <p class="hint">Este archivo no se conecta a internet. Para máxima seguridad también puedes abrirlo en la app oficial: ${OFFICIAL_URL} (pestaña Abrir).</p>
  </section>
  <footer>
    <span>${I("shield")}AES-256-GCM</span>
    <span>${I("offline")}Sin conexión</span>
    <span>${I("lock")}Nada sale de tu equipo</span>
  </footer>
</div>
<script id="payload" type="application/octet-stream">${b64enc(bytes)}<\/script>
<script>${code}<\/script>
</body>
</html>
`;
}

function buildGuide(l) {
  const opening = l.asEnc
    ? `  1. Descarga el archivo "${l.outName}" en tu computador.\r\n` +
      `  2. Abre la app oficial: ${OFFICIAL_URL}\r\n` +
      `  3. Ve a la pestaña "Abrir", carga el archivo y escribe la clave.\r\n` +
      `  4. Pulsa "Abrir y descargar".\r\n`
    : `  1. Descarga el archivo "${l.outName}" en tu computador.\r\n` +
      `  2. Ábrelo con doble clic (se abre en tu navegador, sin internet).\r\n` +
      `  3. Escribe la clave y pulsa "Abrir archivo".\r\n` +
      `     También puedes abrirlo en la app oficial: ${OFFICIAL_URL}\r\n`;
  return `INSTRUCTIVO — Cómo abrir el archivo protegido\r\n\r\n` +
    `Recibiste el archivo:  ${l.outName}\r\n` +
    `Está protegido con una clave que te entregarán por otro medio.\r\n\r\n` +
    `PASOS\r\n\r\n` + opening +
    `  Se descargará el documento original, listo para abrir.\r\n` +
    (/\.zip$/i.test(l.name) ? `  Es una carpeta comprimida: ábrela con doble clic para ver su contenido.\r\n` : "") + `\r\n` +
    `IMPORTANTE\r\n\r\n` +
    `  Si olvidas la clave, el archivo no se podrá abrir.\r\n` +
    `  Guárdala en un lugar seguro y no la compartas.\r\n` +
    `  Si la pierdes, pide a quien te envió el archivo que lo vuelva a enviar.\r\n`;
}

setMode("enc");
renderMaster();
if (new URLSearchParams(location.search).has("maestra")) $("master").showModal();
