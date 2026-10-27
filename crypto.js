// crypto.js — 公開データの復号。形式は crypto_box.py と共通 (変える時は両方を同時に変えること)。
//   鍵素材 = PBKDF2-SHA256(パスワード, salt, iterations, 64バイト)
//   前半32バイト = AES-GCM の鍵、後半32バイト = ファイル名用 HMAC の鍵
//   ファイル = nonce(12バイト) + AES-GCM(gzip(JSON))

const te = new TextEncoder();

export function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

export async function deriveKeyMaterial(password, saltB64, iterations) {
  const base = await crypto.subtle.importKey(
    "raw", te.encode(password.normalize("NFC")), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: b64ToBytes(saltB64), iterations }, base, 512);
  return new Uint8Array(bits);
}

export async function importKeys(material) {
  const encKey = await crypto.subtle.importKey(
    "raw", material.slice(0, 32), { name: "AES-GCM" }, false, ["decrypt"]);
  const nameKey = await crypto.subtle.importKey(
    "raw", material.slice(32, 64), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return { encKey, nameKey };
}

export async function fileId(nameKey, logical) {
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", nameKey, te.encode(logical)));
  let hex = "";
  for (let i = 0; i < 8; i++) hex += sig[i].toString(16).padStart(2, "0");
  return hex;
}

export async function openSealed(encKey, buf) {
  const u8 = new Uint8Array(buf);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: u8.slice(0, 12) }, encKey, u8.slice(12));
  const stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"));
  return JSON.parse(await new Response(stream).text());
}
