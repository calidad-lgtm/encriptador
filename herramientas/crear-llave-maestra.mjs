#!/usr/bin/env node
// Crea la llave maestra de recuperación del Encriptador.
//
//   llave-maestra/llave-maestra.privada.json  Solo para ti. Cifrada con tu contraseña. NO se sube a GitHub.
//   llave-publica.json                        Va dentro de la app. Protege archivos, pero no puede abrirlos.
//
// Uso:  node herramientas/crear-llave-maestra.mjs
import { webcrypto as crypto } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PRIV_DIR = path.join(ROOT, "llave-maestra");
const PRIV_FILE = path.join(PRIV_DIR, "llave-maestra.privada.json");
const PUB_FILE = path.join(ROOT, "llave-publica.json");
const ITER = 600000;

const b64 = bytes => Buffer.from(bytes).toString("base64");
const hex = bytes => Buffer.from(bytes).toString("hex");

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: !!process.stdin.isTTY });
rl._writeToOutput = () => {}; // no mostrar lo que se escribe
const lines = rl[Symbol.asyncIterator]();
async function askHidden(question) {
  process.stdout.write(question);
  const { value, done } = await lines.next();
  process.stdout.write("\n");
  if (done) { console.error("Cancelado."); process.exit(1); }
  return value;
}

if (fs.existsSync(PRIV_FILE)) {
  console.error(`\nYa existe una llave maestra en:\n  ${PRIV_FILE}\n\nNo se creó otra para no perder la actual.`);
  process.exit(1);
}

console.log("\n=== Crear llave maestra del Encriptador ===\n");
console.log("Elige una contraseña larga (mínimo 12 caracteres). No se mostrará mientras escribes.\n");

let password;
for (;;) {
  password = await askHidden("Contraseña: ");
  if (password.length < 12) { console.log("Muy corta. Debe tener al menos 12 caracteres.\n"); continue; }
  if (await askHidden("Repite la contraseña: ") !== password) { console.log("No coinciden. Inténtalo de nuevo.\n"); continue; }
  break;
}
rl.close();

console.log("\nGenerando llave…");
const pair = await crypto.subtle.generateKey(
  { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true, ["encrypt", "decrypt"]);
const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
const id = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", spki))).slice(0, 16);

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
const kek = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" },
  base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, pkcs8));

fs.mkdirSync(PRIV_DIR, { recursive: true });
fs.writeFileSync(PRIV_FILE, JSON.stringify({
  tipo: "encriptador-llave-maestra", version: 1, id, creada: new Date().toISOString(),
  kdf: { nombre: "PBKDF2-SHA256", iteraciones: ITER, salt: b64(salt) }, iv: b64(iv), datos: b64(sealed),
}, null, 2) + "\n", { mode: 0o600 });
fs.writeFileSync(PUB_FILE, JSON.stringify({ id, spki: b64(spki) }, null, 2) + "\n");

console.log(`
Listo. Llave maestra creada (id ${id}).

  Llave privada (solo tuya):  ${PRIV_FILE}
  Llave pública (para la app): ${PUB_FILE}

IMPORTANTE
  - Haz una copia de la llave privada en un pendrive o lugar seguro.
  - Si pierdes la llave privada o su contraseña, no se podrá recuperar ningún archivo.
  - Nunca la compartas ni la subas a internet.
`);
