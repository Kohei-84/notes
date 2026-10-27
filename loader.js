// loader.js — パスワードを確かめて、暗号化された画面を読み込む。
// 公開側に平文で置く画面のコードはこれだけ (何のページかは書かない)。本体は暗号化した "ui" に入っている。
import {
  b64ToBytes, bytesToB64, deriveKeyMaterial, importKeys, fileId, openSealed,
} from "./crypto.js?v=fd4d5fc6d5";

const KEY_STORE = "hn_key";
const root = document.getElementById("app");
let meta = null;
let keys = null;
let index = null;

// 鍵が合わない (パスワード違い・変更) ことを、通信エラーと区別するための例外
class KeyError extends Error {}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

async function fetchBin(logical) {
  const id = await fileId(keys.nameKey, logical);
  const isIndex = logical === "index";
  const q = isIndex ? `t=${Date.now()}` : `v=${(index && index.files[logical]) || ""}`;
  let res;
  try {
    res = await fetch(`d/${id}.bin?${q}`, { cache: isIndex ? "no-store" : "default" });
  } catch {
    throw new Error("通信できませんでした。電波の良い所で再読み込みしてください。");
  }
  if (res.status === 404) throw new KeyError("not found");
  if (!res.ok) throw new Error(`読み込みに失敗しました (${res.status})`);
  const buf = await res.arrayBuffer();
  try {
    return await openSealed(keys.encKey, buf);
  } catch {
    throw new KeyError("decrypt failed");
  }
}

function forgetKey() {
  try { localStorage.removeItem(KEY_STORE); } catch { /* 保存できない環境では何もしない */ }
}

async function unlock(material) {
  keys = await importKeys(material);
  index = await fetchBin("index");
  return fetchBin("ui");
}

function fatal(msg) {
  root.innerHTML = `<div class="gate"><p class="err">${esc(msg)}</p>
    <button id="retry" type="button">もう一度読み込む</button></div>`;
  document.getElementById("retry").addEventListener("click", () => location.reload());
}

function launch(ui) {
  const style = document.createElement("style");
  style.textContent = ui.css;
  document.head.appendChild(style);
  const script = document.createElement("script");
  script.src = URL.createObjectURL(new Blob([ui.js], { type: "text/javascript" }));
  script.onload = () => window.__app.start({ index, fetchBin, forgetKey, KeyError });
  script.onerror = () => fatal("画面を読み込めませんでした。再読み込みしてください。");
  document.body.appendChild(script);
}

function showGate(msg = "") {
  root.innerHTML = `<div class="gate"><h1>Notes</h1><p>パスワードを入力してください</p>
    <form id="gf">
      <input type="text" name="username" value="notes" autocomplete="username" hidden>
      <input id="pw" type="password" name="password" autocomplete="current-password" aria-label="パスワード" required>
      <button id="gb" type="submit">開く</button>
    </form><p class="err" id="ge">${esc(msg)}</p></div>`;
  const pw = document.getElementById("pw");
  pw.focus();
  document.getElementById("gf").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = document.getElementById("gb");
    const err = document.getElementById("ge");
    btn.disabled = true;
    btn.textContent = "確認中…";
    err.textContent = "";
    try {
      const material = await deriveKeyMaterial(pw.value, meta.salt, meta.iter);
      const ui = await unlock(material);
      try { localStorage.setItem(KEY_STORE, bytesToB64(material)); } catch { /* 保存できなくても今回は見られる */ }
      launch(ui);
    } catch (e) {
      err.textContent = e instanceof KeyError ? "パスワードが違います" : e.message;
      btn.disabled = false;
      btn.textContent = "開く";
    }
  });
}

async function boot() {
  try {
    const r = await fetch(`meta.json?t=${Date.now()}`, { cache: "no-store" });
    if (!r.ok) throw new Error(String(r.status));
    meta = await r.json();
  } catch {
    return fatal("ページを読み込めませんでした。通信状態を確かめてください。");
  }
  let saved = null;
  try { saved = localStorage.getItem(KEY_STORE); } catch { saved = null; }
  if (saved) {
    try {
      return launch(await unlock(b64ToBytes(saved)));
    } catch (e) {
      if (!(e instanceof KeyError)) return fatal(e.message);
      forgetKey();
      return showGate("パスワードが変わったようです。もう一度入力してください。");
    }
  }
  return showGate();
}

boot();
