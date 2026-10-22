// Núcleo de cifrado del Encriptador.
// Lo usa la app y se copia tal cual dentro de cada archivo protegido (.html), por eso no depende de nada más.
// Solo usa la Web Crypto API del navegador: AES-256-GCM, PBKDF2-SHA-256 y RSA-OAEP-3072 (SHA-256).
"use strict";

const enc = s => new TextEncoder().encode(s);
const toText = b => new TextDecoder().decode(b);
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const aes = raw => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);

const MAGIC1 = enc("ENC1"), MAGIC2 = enc("ENC2"), MAGIC3 = enc("ENC3"), MAGIC4 = enc("ENC4"), MAGIC5 = enc("ENC5");
const ITER = 1000000;                          // PBKDF2 de archivos nuevos (OWASP 2023 recomienda ≥ 600.000)
const MIN_ITER = 100000, MAX_ITER = 20000000;  // límites al leer: un archivo manipulado no puede congelar el equipo
const LEGACY_ITER = 250000;                    // ENC1–ENC4
const SLOT = 76;                               // ENC2–ENC4: salt(16) | iv(12) | llave cifrada(48)
const RSA_MAX = 318;                           // bytes que RSA-OAEP 3072/SHA-256 puede sellar
const OAEP_LABEL = enc("encriptador/ENC5");
const BAD_KEY = "La clave no es correcta. Revísala e inténtalo de nuevo.";
const DAMAGED = "El archivo está dañado o fue modificado. No es seguro usarlo.";

const isMagic = (d, m) => d.length >= 4 && m.every((b, i) => d[i] === b);
const u16 = n => new Uint8Array([(n >>> 8) & 255, n & 255]);
const u32 = n => new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const u64 = n => concat(u32(Math.floor(n / 2 ** 32)), u32(n >>> 0));
const readU16 = (d, o) => (d[o] << 8) | d[o + 1];
const readU32 = (d, o) => d[o] * 2 ** 24 + (d[o + 1] << 16) + (d[o + 2] << 8) + d[o + 3];
const readU64 = (d, o) => readU32(d, o) * 2 ** 32 + readU32(d, o + 4);

// Claves: NFC para que "ñ" o tildes escritas en Mac, Windows o celular den lo mismo; sin espacios en los extremos
const clean = s => s.normalize("NFC").trim();

function generateKey(len = 24) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"; // sin 0/O ni 1/l/I
  const out = [];
  const buf = new Uint8Array(1);
  while (out.length < len) {
    crypto.getRandomValues(buf);
    if (buf[0] < 256 - (256 % chars.length)) out.push(chars[buf[0] % chars.length]); // sin sesgo
  }
  return out.join("").match(/.{1,6}/g).join("-"); // 24 caracteres ≈ 139 bits
}

// Nombre seguro para descargar: sin rutas, caracteres de control ni reservados
const safeName = n => n.replace(/[\u0000-\u001f\u007f/\\:*?"<>|]/g, "_").replace(/^[.\s]+/, "").slice(0, 200) || "archivo";

async function deriveKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", enc(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

// Relleno PADMÉ (mínimo 4 KB): oculta el tamaño exacto del documento con < 12 % de sobrecosto
function padSize(n) {
  if (n <= 4096) return 4096;
  const e = Math.floor(Math.log2(n)), s = Math.floor(Math.log2(e)) + 1, step = 2 ** (e - s);
  return Math.ceil(n / step) * step;
}

// Contenido cifrado (ENC5) = 0x01 | largoNombre(2) | nombre | largoDatos(8) | datos | ceros de relleno
function packInner(name, data) {
  const nb = enc(name.slice(0, 255));
  const out = new Uint8Array(padSize(11 + nb.length + data.length));
  out[0] = 1;
  out.set(u16(nb.length), 1);
  out.set(nb, 3);
  out.set(u64(data.length), 3 + nb.length);
  out.set(data, 11 + nb.length);
  return out;
}
function unpackInner(p, via) {
  if (p[0] !== 1) throw new Error(DAMAGED);
  const n = readU16(p, 1), start = 11 + n, len = readU64(p, 3 + n);
  if (start + len > p.length) throw new Error(DAMAGED);
  return { name: safeName(toText(p.subarray(3, 3 + n))), bytes: p.slice(start, start + len), via };
}

// ENC5
//   cabecera = "ENC5" | iteraciones(4) | salt(16) | ivClave(12) | llaveCifrada(48) | idMaestra(8) | largoSello(2) | sello | ivDatos(12)
//   llaveCifrada = AES-GCM(PBKDF2(clave), llave del archivo)            AAD = "ENC5" | iteraciones | salt
//   sello        = RSA-OAEP(maestra pública, llave del archivo + clave)  etiqueta "encriptador/ENC5"
//   datos        = AES-GCM(llave del archivo, contenido)                 AAD = cabecera completa
// Cambiar cualquier byte de la cabecera o de los datos hace fallar la apertura.
// master = { id: Uint8Array(8), key: CryptoKey pública RSA-OAEP }
async function encrypt(data, name, password, master) {
  const key = clean(password);
  const fileKey = rand(32), salt = rand(16), ivKey = rand(12), ivData = rand(12);
  const kdfPart = concat(MAGIC5, u32(ITER), salt);
  const kek = await deriveKey(key, salt, ITER);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivKey, additionalData: kdfPart }, kek, fileKey));
  const withKey = concat(fileKey, enc(key));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP", label: OAEP_LABEL }, master.key,
    withKey.length <= RSA_MAX ? withKey : fileKey));
  const header = concat(kdfPart, ivKey, wrapped, master.id, u16(sealed.length), sealed, ivData);
  const inner = packInner(name, data);
  const body = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivData, additionalData: header }, await aes(fileKey), inner));
  fileKey.fill(0); withKey.fill(0); inner.fill(0); // no dejar copias en memoria
  return concat(header, body);
}

function parse5(d) {
  if (d.length < 4 + 4 + 16 + 12 + 48 + 8 + 2 + 12 + 16) throw new Error(DAMAGED);
  let o = 4;
  const iterations = readU32(d, o); o += 4;
  const salt = d.subarray(o, o += 16), ivKey = d.subarray(o, o += 12), wrapped = d.subarray(o, o += 48);
  const masterId = d.subarray(o, o += 8);
  const n = readU16(d, o); o += 2;
  const sealed = d.subarray(o, o += n), ivData = d.subarray(o, o += 12);
  if (o + 16 > d.length || iterations < MIN_ITER || iterations > MAX_ITER) throw new Error(DAMAGED);
  return { iterations, salt, ivKey, wrapped, masterId, sealed, ivData,
    kdfPart: d.subarray(0, 24), header: d.subarray(0, o), body: d.subarray(o) };
}
async function openBody5(fileKey, p, via) {
  let plain;
  try { plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: p.ivData, additionalData: p.header }, await aes(fileKey), p.body)); }
  catch { throw new Error(DAMAGED); }
  finally { fileKey.fill(0); }
  const r = unpackInner(plain, via);
  plain.fill(0);
  return r;
}

// --- Formatos anteriores (solo para abrir) ---
function parse3(d) {
  let o = 4;
  const slot = d.subarray(o, o += SLOT), id = d.subarray(o, o += 8);
  const n = readU16(d, o); o += 2;
  const sealed = d.subarray(o, o += n), iv = d.subarray(o, o += 12);
  if (o + 16 > d.length) throw new Error(DAMAGED);
  return { slot, id, sealed, iv, body: d.subarray(o) };
}
async function unwrapLegacy(slot, password) {
  const kek = await deriveKey(password.trim(), slot.slice(0, 16), LEGACY_ITER);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: slot.slice(16, 28) }, kek, slot.slice(28)));
}
async function openLegacy(fileKey, iv, body, via) {
  let plain;
  try { plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, await aes(fileKey), body)); }
  catch { throw new Error(DAMAGED); }
  const n = readU16(plain, 0);
  return { name: safeName(toText(plain.subarray(2, 2 + n))), bytes: plain.slice(2 + n), via };
}

async function decrypt(data, password) {
  if (isMagic(data, MAGIC5)) {
    const p = parse5(data);
    let fileKey;
    try {
      const kek = await deriveKey(clean(password), p.salt, p.iterations);
      fileKey = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: p.ivKey, additionalData: p.kdfPart }, kek, p.wrapped));
    } catch { throw new Error(BAD_KEY); }
    return openBody5(fileKey, p, "la clave");
  }
  if (isMagic(data, MAGIC3) || isMagic(data, MAGIC4)) {
    const p = parse3(data);
    let fileKey;
    try { fileKey = await unwrapLegacy(p.slot, password); } catch { throw new Error(BAD_KEY); }
    return openLegacy(fileKey, p.iv, p.body, "la clave");
  }
  if (data.length > 4 + 2 * SLOT + 12 && isMagic(data, MAGIC2)) {
    let fileKey;
    for (const slot of [data.subarray(4, 4 + SLOT), data.subarray(4 + SLOT, 4 + 2 * SLOT)]) {
      try { fileKey = await unwrapLegacy(slot, password); break; } catch {}
    }
    if (!fileKey) throw new Error(BAD_KEY);
    const off = 4 + 2 * SLOT;
    return openLegacy(fileKey, data.subarray(off, off + 12), data.subarray(off + 12), "la clave");
  }
  if (data.length >= 32 && isMagic(data, MAGIC1)) {
    const key = await deriveKey(password, data.slice(4, 20), LEGACY_ITER);
    let plain;
    try { plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.slice(20, 32) }, key, data.slice(32))); }
    catch { throw new Error(BAD_KEY); }
    const n = readU16(plain, 0);
    return { name: safeName(toText(plain.subarray(2, 2 + n))), bytes: plain.slice(2 + n), via: "la clave" };
  }
  throw new Error("Este archivo no fue creado con este encriptador.");
}

// Recupera un archivo con la llave maestra privada, sin la clave. Devuelve también la clave original si quedó sellada.
async function decryptMaster(data, master) {
  const v5 = isMagic(data, MAGIC5);
  if (!v5 && !isMagic(data, MAGIC3) && !isMagic(data, MAGIC4))
    throw new Error("Este archivo fue protegido con una versión anterior, sin llave maestra. Solo se abre con su clave.");
  const p = v5 ? parse5(data) : parse3(data);
  const id = v5 ? p.masterId : p.id;
  if (id.some((b, i) => b !== master.id[i])) throw new Error("Este archivo fue protegido con otra llave maestra.");
  let opened;
  try { opened = new Uint8Array(await crypto.subtle.decrypt(v5 ? { name: "RSA-OAEP", label: OAEP_LABEL } : { name: "RSA-OAEP" }, master.key, p.sealed)); }
  catch { throw new Error("La llave maestra no abre este archivo."); }
  const key = opened.length > 32 && !isMagic(data, MAGIC3) ? toText(opened.subarray(32)) : null;
  const r = v5 ? await openBody5(opened.slice(0, 32), p, "la llave maestra")
               : await openLegacy(opened.slice(0, 32), p.iv, p.body, "la llave maestra");
  opened.fill(0);
  r.key = key;
  return r;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function b64enc(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function b64dec(str) {
  const s = atob(str.replace(/\s+/g, ""));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function download(bytes, name, type = "application/octet-stream") {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: safeName(name) });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
