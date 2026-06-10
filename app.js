"use strict";

/* ============================================================================
 * v2ray Sub Decoder — клиентский декодер подписок.
 * Поддержка: vmess:// vless:// ss:// trojan://
 * Выходы: JSON, vless-ссылки, нативные ссылки, конфиг xray.
 * Всё выполняется в браузере.
 * ========================================================================== */

/* ----------------------------- base64 / utils ---------------------------- */

// Толерантное декодирование base64: принимает standard и url-safe, с/без паддинга.
function decodeBase64(s) {
  if (!s) return null;
  s = s.trim().replace(/[\r\n\t ]/g, "");
  if (!s) return null;
  let std = s.replace(/-/g, "+").replace(/_/g, "/");
  while (std.length % 4 !== 0) std += "=";
  try {
    const bin = atob(std);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8").decode(bytes);
  } catch (e) {
    return null;
  }
}

// Кодирование строки в base64 (UTF-8 safe).
function encodeBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

function orDefault(v, def) {
  return v && String(v).trim() !== "" ? v : def;
}

function splitComma(s) {
  if (!s) return [];
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

function truthy(s) {
  return ["1", "true", "yes", "on"].includes(String(s).trim().toLowerCase());
}

// Русское склонление: 1 нода / 2 ноды / 5 нод.
function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}
function nodesWord(n) {
  return `${n} ${plural(n, "нода", "ноды", "нод")}`;
}

function toInt(v) {
  if (typeof v === "number") return Math.trunc(v);
  const n = parseInt(String(v).trim(), 10);
  return Number.isNaN(n) ? 0 : n;
}

/* ----------------------------- парсинг ---------------------------------- */

function looksLikeLinks(s) {
  return ["vmess://", "vless://", "ss://", "trojan://"].some((p) => s.includes(p));
}

// Разбор всей подписки -> { nodes, errors }
function parseSubscription(body) {
  body = body.replace(/^﻿/, "").trim();

  let text = body;
  const dec = decodeBase64(body);
  if (dec && looksLikeLinks(dec)) text = dec;

  const nodes = [];
  const errors = [];
  for (let line of text.split("\n")) {
    line = line.replace(/^﻿/, "").trim();
    if (!line || line.startsWith("//") || line.startsWith("#")) continue;
    try {
      nodes.push(parseLink(line));
    } catch (e) {
      errors.push(`${line.slice(0, 40)}…: ${e.message}`);
    }
  }
  return { nodes, errors };
}

function parseLink(link) {
  if (link.startsWith("vmess://")) return parseVmess(link);
  if (link.startsWith("vless://")) return parseVless(link);
  if (link.startsWith("ss://")) return parseSS(link);
  if (link.startsWith("trojan://")) return parseTrojan(link);
  throw new Error("неизвестная схема");
}

function parseVmess(link) {
  const payload = link.slice("vmess://".length);
  const dec = decodeBase64(payload);
  if (!dec) throw new Error("vmess: плохой base64");
  let v;
  try {
    v = JSON.parse(dec);
  } catch (e) {
    throw new Error("vmess: плохой json");
  }
  const net = orDefault(v.net, "tcp");
  const node = {
    protocol: "vmess",
    name: v.ps || "",
    server: v.add || "",
    port: toInt(v.port),
    uuid: v.id || "",
    alter_id: toInt(v.aid),
    cipher: orDefault(v.scy, "auto"),
    network: net,
    security: v.tls === "tls" || v.tls === "xtls" ? v.tls : "none",
    sni: v.sni || "",
    host: v.host || "",
    path: v.path || "",
    alpn: v.alpn || "",
    fingerprint: v.fp || "",
    header_type: v.type || "",
    raw: link,
  };
  if (net === "grpc") node.service_name = v.path || "";
  return node;
}

// Разбор authority-схем (vless/trojan) c username@host:port?query#frag.
function parseAuthorityURI(link) {
  const u = new URL(link);
  const q = u.searchParams;
  return { u, q };
}

function parseVless(link) {
  const { u, q } = parseAuthorityURI(link);
  return {
    protocol: "vless",
    name: u.hash ? decodeURIComponent(u.hash.slice(1)) : "",
    server: u.hostname,
    port: toInt(u.port),
    uuid: decodeURIComponent(u.username),
    network: orDefault(q.get("type"), "tcp"),
    security: orDefault(q.get("security"), "none"),
    flow: q.get("flow") || "",
    sni: q.get("sni") || "",
    host: q.get("host") || "",
    path: q.get("path") || "",
    alpn: q.get("alpn") || "",
    fingerprint: q.get("fp") || "",
    service_name: q.get("serviceName") || "",
    header_type: q.get("headerType") || "",
    public_key: q.get("pbk") || "",
    short_id: q.get("sid") || "",
    spider_x: q.get("spx") || "",
    allow_insecure: truthy(q.get("allowInsecure")),
    raw: link,
  };
}

function parseTrojan(link) {
  const { u, q } = parseAuthorityURI(link);
  return {
    protocol: "trojan",
    name: u.hash ? decodeURIComponent(u.hash.slice(1)) : "",
    server: u.hostname,
    port: toInt(u.port),
    password: decodeURIComponent(u.username),
    network: orDefault(q.get("type"), "tcp"),
    security: orDefault(q.get("security"), "tls"),
    flow: q.get("flow") || "",
    sni: q.get("sni") || "",
    host: q.get("host") || "",
    path: q.get("path") || "",
    alpn: q.get("alpn") || "",
    fingerprint: q.get("fp") || "",
    service_name: q.get("serviceName") || "",
    header_type: q.get("headerType") || "",
    allow_insecure: truthy(q.get("allowInsecure")),
    raw: link,
  };
}

function parseSS(link) {
  let rest = link.slice("ss://".length);
  let name = "";
  const hashIdx = rest.indexOf("#");
  if (hashIdx >= 0) {
    name = decodeURIComponent(rest.slice(hashIdx + 1));
    rest = rest.slice(0, hashIdx);
  }
  const qIdx = rest.indexOf("?");
  if (qIdx >= 0) rest = rest.slice(0, qIdx); // отбрасываем plugin-параметры

  let method, password, host, portStr;
  const at = rest.lastIndexOf("@");
  if (at >= 0) {
    // SIP002: ss://base64(method:password)@host:port
    let creds = rest.slice(0, at);
    const hostPort = rest.slice(at + 1);
    const decCreds = decodeBase64(creds);
    if (decCreds) creds = decCreds;
    [method, password] = splitCred(creds);
    [host, portStr] = splitHostPort(hostPort);
  } else {
    // legacy: ss://base64(method:password@host:port)
    const dec = decodeBase64(rest);
    if (!dec) throw new Error("ss: плохой base64");
    const atd = dec.lastIndexOf("@");
    if (atd < 0) throw new Error("ss: нет '@' в данных");
    [method, password] = splitCred(dec.slice(0, atd));
    [host, portStr] = splitHostPort(dec.slice(atd + 1));
  }

  return {
    protocol: "shadowsocks",
    name,
    server: host,
    port: toInt(portStr),
    cipher: method,
    password,
    network: "tcp",
    security: "none",
    raw: link,
  };
}

function splitCred(s) {
  const i = s.indexOf(":");
  return i >= 0 ? [s.slice(0, i), s.slice(i + 1)] : [s, ""];
}
function splitHostPort(s) {
  const i = s.lastIndexOf(":");
  return i >= 0 ? [s.slice(0, i), s.slice(i + 1)] : [s, ""];
}

/* ----------------------------- генерация вывода -------------------------- */

// Чистим пустые поля для JSON-вывода (как omitempty в Go).
function cleanNode(n) {
  const out = {};
  for (const [k, v] of Object.entries(n)) {
    if (v === "" || v === 0 || v === false || v == null) {
      // оставляем значащие поля даже при нулях
      if (["protocol", "name", "server", "port"].includes(k)) out[k] = v;
      continue;
    }
    out[k] = v;
  }
  return out;
}

function toJSON(nodes) {
  return JSON.stringify(nodes.map(cleanNode), null, 2);
}

function hostPort(host, port) {
  if (host.includes(":") && !host.startsWith("[")) host = `[${host}]`;
  return `${host}:${port}`;
}

function tlsField(security) {
  return ["tls", "xtls", "reality"].includes(security) ? security : "";
}

function toURI(n) {
  switch (n.protocol) {
    case "vmess":
      return vmessURI(n);
    case "vless":
      return schemeURI("vless", n.uuid, n);
    case "trojan":
      return schemeURI("trojan", n.password, n);
    case "shadowsocks":
      return ssURI(n);
    default:
      return "";
  }
}

function vmessURI(n) {
  const m = {
    v: "2",
    ps: n.name || "",
    add: n.server,
    port: String(n.port),
    id: n.uuid,
    aid: String(n.alter_id || 0),
    scy: orDefault(n.cipher, "auto"),
    net: orDefault(n.network, "tcp"),
    type: n.header_type || "",
    host: n.host || "",
    path: n.path || "",
    tls: tlsField(n.security),
    sni: n.sni || "",
    alpn: n.alpn || "",
    fp: n.fingerprint || "",
  };
  return "vmess://" + encodeBase64(JSON.stringify(m));
}

function schemeURI(scheme, userinfo, n) {
  const q = new URLSearchParams();
  const set = (k, v) => { if (v) q.set(k, v); };
  if (scheme === "vless") q.set("encryption", "none");
  set("security", n.security);
  set("type", n.network);
  set("flow", n.flow);
  set("sni", n.sni);
  set("host", n.host);
  set("path", n.path);
  set("alpn", n.alpn);
  set("fp", n.fingerprint);
  set("serviceName", n.service_name);
  set("headerType", n.header_type);
  set("pbk", n.public_key);
  set("sid", n.short_id);
  set("spx", n.spider_x);
  if (n.allow_insecure) q.set("allowInsecure", "1");

  const frag = n.name ? "#" + encodeURIComponent(n.name) : "";
  return `${scheme}://${encodeURIComponent(userinfo)}@${hostPort(n.server, n.port)}?${q.toString()}${frag}`;
}

function ssURI(n) {
  const creds = encodeBase64(`${n.cipher}:${n.password}`).replace(/=+$/, "");
  let s = `ss://${creds}@${hostPort(n.server, n.port)}`;
  if (n.name) s += "#" + encodeURIComponent(n.name);
  return s;
}

function toLinks(nodes) {
  return nodes.map(toURI).filter(Boolean).join("\n");
}

function toVless(nodes) {
  const vless = nodes.filter((n) => n.protocol === "vless");
  return { text: vless.map(toURI).join("\n"), skipped: nodes.length - vless.length };
}

/* ----------------------------- конфиг xray ------------------------------ */

function buildStreamSettings(n) {
  const network = orDefault(n.network, "tcp");
  const security = orDefault(n.security, "none");
  if (network === "tcp" && security === "none" && !n.header_type) return null;

  const ss = { network, security };

  if (security === "tls" || security === "xtls") {
    const tls = {};
    if (n.sni) tls.serverName = n.sni;
    const al = splitComma(n.alpn);
    if (al.length) tls.alpn = al;
    if (n.fingerprint) tls.fingerprint = n.fingerprint;
    if (n.allow_insecure) tls.allowInsecure = true;
    ss.tlsSettings = tls;
  } else if (security === "reality") {
    const r = { serverName: n.sni || "", publicKey: n.public_key || "", shortId: n.short_id || "" };
    if (n.fingerprint) r.fingerprint = n.fingerprint;
    if (n.spider_x) r.spiderX = n.spider_x;
    ss.realitySettings = r;
  }

  switch (network) {
    case "ws": {
      const ws = { path: orDefault(n.path, "/") };
      if (n.host) ws.headers = { Host: n.host };
      ss.wsSettings = ws;
      break;
    }
    case "grpc":
      ss.grpcSettings = { serviceName: orDefault(n.service_name, n.path || "") };
      break;
    case "h2":
    case "http": {
      const h2 = { path: orDefault(n.path, "/") };
      const hosts = splitComma(n.host);
      if (hosts.length) h2.host = hosts;
      ss.httpSettings = h2;
      break;
    }
    case "tcp":
      if (n.header_type === "http") ss.tcpSettings = { header: { type: "http" } };
      break;
  }
  return ss;
}

function buildOutbound(n, tag) {
  const out = { tag, protocol: n.protocol };
  switch (n.protocol) {
    case "vmess":
      out.settings = { vnext: [{ address: n.server, port: n.port, users: [{ id: n.uuid, alterId: n.alter_id || 0, security: orDefault(n.cipher, "auto") }] }] };
      break;
    case "vless": {
      const user = { id: n.uuid, encryption: "none" };
      if (n.flow) user.flow = n.flow;
      out.settings = { vnext: [{ address: n.server, port: n.port, users: [user] }] };
      break;
    }
    case "trojan":
      out.settings = { servers: [{ address: n.server, port: n.port, password: n.password }] };
      break;
    case "shadowsocks":
      out.settings = { servers: [{ address: n.server, port: n.port, method: n.cipher, password: n.password }] };
      break;
  }
  const ss = buildStreamSettings(n);
  if (ss) out.streamSettings = ss;
  return out;
}

function buildConfig(nodes) {
  const outbounds = nodes.map((n, i) => buildOutbound(n, i === 0 ? "proxy" : `proxy-${i}`));
  outbounds.push(
    { tag: "direct", protocol: "freedom", settings: {} },
    { tag: "block", protocol: "blackhole", settings: {} }
  );
  const cfg = {
    log: { loglevel: "warning" },
    inbounds: [
      { tag: "socks-in", listen: "127.0.0.1", port: 10808, protocol: "socks", settings: { udp: true, auth: "noauth" } },
      { tag: "http-in", listen: "127.0.0.1", port: 10809, protocol: "http", settings: {} },
    ],
    outbounds,
    routing: { domainStrategy: "AsIs", rules: [{ type: "field", ip: ["geoip:private"], outboundTag: "direct" }] },
  };
  return JSON.stringify(cfg, null, 2);
}

/* ----------------------------- загрузка по URL -------------------------- */

async function fetchSubscription(url, mode) {
  let target = url;
  if (mode === "allorigins") {
    target = "https://api.allorigins.win/raw?url=" + encodeURIComponent(url);
  } else if (mode === "corsproxy") {
    target = "https://corsproxy.io/?url=" + encodeURIComponent(url);
  }
  const resp = await fetch(target, { headers: { "User-Agent": "v2rayN/6.0" } });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return await resp.text();
}

/* ----------------------------- UI --------------------------------------- */

const els = {
  url: document.getElementById("subUrl"),
  text: document.getElementById("subText"),
  mode: document.getElementById("loadMode"),
  decode: document.getElementById("decodeBtn"),
  decodeText: document.getElementById("decodeTextBtn"),
  status: document.getElementById("status"),
  results: document.getElementById("results"),
  output: document.getElementById("output"),
  count: document.getElementById("count"),
  tabs: document.getElementById("tabs"),
  copy: document.getElementById("copyBtn"),
  download: document.getElementById("downloadBtn"),
  repoLink: document.getElementById("repoLink"),
};

let current = { nodes: [], tab: "json" };

const RENDER = {
  json: (n) => toJSON(n),
  vless: (n) => toVless(n).text || "// нет vless-нод в подписке",
  links: (n) => toLinks(n),
  config: (n) => buildConfig(n),
};
const FILENAME = { json: "nodes.json", vless: "vless.txt", links: "links.txt", config: "config.json" };

function showStatus(type, html) {
  els.status.className = `status ${type}`;
  els.status.innerHTML = html;
  els.status.classList.remove("hidden");
}
function hideStatus() { els.status.classList.add("hidden"); }

function renderOutput() {
  els.output.textContent = RENDER[current.tab](current.nodes);
}

function showResults(nodes, errors) {
  current.nodes = nodes;
  els.count.textContent = nodesWord(nodes.length);
  els.results.classList.remove("hidden");
  renderOutput();

  if (errors && errors.length) {
    showStatus(
      "info",
      `Разобрано: <b>${nodesWord(nodes.length)}</b>. Пропущено строк: ${errors.length}.` +
        `<ul class="errlist">${errors.slice(0, 8).map((e) => `<li>${escapeHtml(e)}</li>`).join("")}</ul>`
    );
  } else {
    showStatus("success", `Разобрано: <b>${nodesWord(nodes.length)}</b>.`);
  }
}

function escapeHtml(s) {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function decodeFromText(body) {
  const { nodes, errors } = parseSubscription(body);
  if (nodes.length === 0) {
    showStatus("error", "Не удалось разобрать ни одной ноды. Проверь формат подписки.");
    els.results.classList.add("hidden");
    return;
  }
  showResults(nodes, errors);
}

async function decodeFromUrl() {
  const url = els.url.value.trim();
  if (!url) { showStatus("error", "Введите URL подписки."); return; }
  els.decode.disabled = true;
  showStatus("info", "Загрузка подписки…");
  try {
    const body = await fetchSubscription(url, els.mode.value);
    decodeFromText(body);
  } catch (e) {
    showStatus(
      "error",
      `Не удалось загрузить: ${escapeHtml(e.message)}.<br>` +
        `Попробуй другой способ загрузки (прокси) или вставь содержимое подписки вручную.`
    );
  } finally {
    els.decode.disabled = false;
  }
}

// События
els.decode.addEventListener("click", decodeFromUrl);
els.url.addEventListener("keydown", (e) => { if (e.key === "Enter") decodeFromUrl(); });
els.decodeText.addEventListener("click", () => {
  const body = els.text.value.trim();
  if (!body) { showStatus("error", "Вставьте содержимое подписки."); return; }
  decodeFromText(body);
});

els.tabs.addEventListener("click", (e) => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  current.tab = btn.dataset.tab;
  els.tabs.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === btn));
  if (current.nodes.length) renderOutput();
});

els.copy.addEventListener("click", async () => {
  await navigator.clipboard.writeText(els.output.textContent);
  els.copy.textContent = "Скопировано ✓";
  setTimeout(() => (els.copy.textContent = "Копировать"), 1500);
});

els.download.addEventListener("click", () => {
  const blob = new Blob([els.output.textContent], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = FILENAME[current.tab];
  a.click();
  URL.revokeObjectURL(a.href);
});

// Ссылка на репозиторий из имени GitHub Pages (user.github.io/repo).
(function setRepoLink() {
  const host = location.hostname;
  if (host.endsWith("github.io")) {
    const user = host.split(".")[0];
    const repo = location.pathname.split("/").filter(Boolean)[0] || "";
    els.repoLink.href = `https://github.com/${user}/${repo}`;
  } else {
    els.repoLink.style.display = "none";
  }
})();
