"use strict";

/* ============================================================================
 * Менеджер подписок на приватном GitHub Gist.
 * Авторизация — личный токен GitHub (scope: gist), который хранится только в
 * localStorage этого браузера. Один и тот же токен на разных устройствах даёт
 * доступ к одному и тому же списку подписок (cross-device).
 *
 * Использует глобальные функции из app.js: fetchSubscription, parseSubscription,
 * showResults, showStatus, els (поля ввода/вывода).
 * ========================================================================== */

const GIST_FILE = "v2sub-decoder.json";
const GIST_DESC = "v2ray Sub Decoder — saved subscriptions";
const LS_TOKEN = "v2sub.token";
const LS_GISTID = "v2sub.gistId";

class GistStore {
  constructor(token) {
    this.token = token;
    this.gistId = null;
    this.data = { subscriptions: [] };
  }

  headers(extra) {
    return Object.assign(
      {
        Authorization: `Bearer ${this.token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      extra || {}
    );
  }

  // Находит существующий gist с нашим файлом или создаёт новый.
  async init() {
    const cached = localStorage.getItem(LS_GISTID);
    if (cached) {
      try {
        await this.load(cached);
        this.gistId = cached;
        return;
      } catch (e) {
        /* кэш устарел — ищем заново */
      }
    }
    const resp = await fetch("https://api.github.com/gists?per_page=100", {
      headers: this.headers(),
    });
    if (resp.status === 401) throw new Error("Неверный или просроченный токен");
    if (!resp.ok) throw new Error("GitHub API: HTTP " + resp.status);
    const gists = await resp.json();
    const found = gists.find((g) => g.files && g.files[GIST_FILE]);
    if (found) {
      this.gistId = found.id;
      await this.load(found.id);
    } else {
      await this.create();
    }
    localStorage.setItem(LS_GISTID, this.gistId);
  }

  async load(id) {
    const r = await fetch("https://api.github.com/gists/" + id, { headers: this.headers() });
    if (!r.ok) throw new Error("Не удалось загрузить gist (HTTP " + r.status + ")");
    const g = await r.json();
    const f = g.files && g.files[GIST_FILE];
    let content = f ? f.content : "";
    if (f && f.truncated && f.raw_url) {
      content = await (await fetch(f.raw_url)).text();
    }
    try {
      this.data = content ? JSON.parse(content) : { subscriptions: [] };
    } catch (e) {
      this.data = { subscriptions: [] };
    }
    if (!Array.isArray(this.data.subscriptions)) this.data.subscriptions = [];
  }

  async create() {
    const body = {
      description: GIST_DESC,
      public: false,
      files: { [GIST_FILE]: { content: JSON.stringify(this.data, null, 2) } },
    };
    const r = await fetch("https://api.github.com/gists", {
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error("Не удалось создать gist (HTTP " + r.status + ")");
    const g = await r.json();
    this.gistId = g.id;
  }

  async save() {
    const body = { files: { [GIST_FILE]: { content: JSON.stringify(this.data, null, 2) } } };
    const r = await fetch("https://api.github.com/gists/" + this.gistId, {
      method: "PATCH",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error("Не удалось сохранить (HTTP " + r.status + ")");
  }

  list() {
    return this.data.subscriptions;
  }

  async add(sub) {
    sub.id = (crypto.randomUUID && crypto.randomUUID()) || String(Date.now());
    sub.addedAt = new Date().toISOString();
    this.data.subscriptions.push(sub);
    await this.save();
  }

  async remove(id) {
    this.data.subscriptions = this.data.subscriptions.filter((s) => s.id !== id);
    await this.save();
  }

  async update(id, patch) {
    const s = this.data.subscriptions.find((x) => x.id === id);
    if (s) Object.assign(s, patch);
    await this.save();
  }
}

/* ----------------------------- UI ---------------------------------------- */

const mgr = {
  store: null,
  el: {
    token: document.getElementById("mgrToken"),
    loginBtn: document.getElementById("mgrLoginBtn"),
    login: document.getElementById("mgrLogin"),
    panel: document.getElementById("mgrPanel"),
    list: document.getElementById("mgrList"),
    state: document.getElementById("mgrState"),
    saveCurrent: document.getElementById("mgrSaveCurrent"),
    refreshAll: document.getElementById("mgrRefreshAll"),
    logout: document.getElementById("mgrLogout"),
  },
};

function mgrSetState(text, cls) {
  mgr.el.state.textContent = text;
  mgr.el.state.className = "manager-state" + (cls ? " " + cls : "");
}

function modeLabel(m) {
  return { direct: "прямой", allorigins: "allorigins", corsproxy: "corsproxy" }[m] || m || "—";
}

function renderList() {
  const subs = mgr.store.list();
  mgr.el.list.innerHTML = "";
  if (subs.length === 0) {
    const li = document.createElement("li");
    li.className = "sub-empty";
    li.textContent = "Пока нет сохранённых подписок. Введи URL выше и нажми «Сохранить текущий URL».";
    mgr.el.list.appendChild(li);
    return;
  }
  for (const s of subs) {
    const li = document.createElement("li");
    li.className = "sub-item";

    const info = document.createElement("div");
    info.className = "sub-info";
    const name = document.createElement("div");
    name.className = "sub-name";
    name.textContent = s.name || "(без названия)";
    const url = document.createElement("div");
    url.className = "sub-url";
    url.textContent = s.url;
    url.title = s.url;
    const meta = document.createElement("div");
    meta.className = "sub-meta";
    meta.textContent = `загрузка: ${modeLabel(s.mode)}`;
    info.append(name, url, meta);

    const actions = document.createElement("div");
    actions.className = "sub-actions";
    const decodeBtn = document.createElement("button");
    decodeBtn.className = "btn small";
    decodeBtn.textContent = "Декодировать";
    decodeBtn.addEventListener("click", () => decodeSaved(s));
    const delBtn = document.createElement("button");
    delBtn.className = "btn small danger";
    delBtn.textContent = "✕";
    delBtn.title = "Удалить";
    delBtn.addEventListener("click", () => removeSaved(s));
    actions.append(decodeBtn, delBtn);

    li.append(info, actions);
    mgr.el.list.appendChild(li);
  }
}

// Загружает сохранённую подписку через общий пайплайн декодера из app.js.
async function decodeSaved(s) {
  els.url.value = s.url;
  if (s.mode) els.mode.value = s.mode;
  showStatus("info", `Загрузка «${escapeHtml(s.name || s.url)}»…`);
  try {
    const body = await fetchSubscription(s.url, s.mode || "allorigins");
    decodeFromText(body);
  } catch (e) {
    showStatus(
      "error",
      `Не удалось загрузить «${escapeHtml(s.name || s.url)}»: ${escapeHtml(e.message)}.<br>` +
        `Попробуй сменить способ загрузки у подписки или вставить содержимое вручную.`
    );
  }
}

async function removeSaved(s) {
  if (!confirm(`Удалить подписку «${s.name || s.url}»?`)) return;
  mgrSetState("Сохранение…");
  try {
    await mgr.store.remove(s.id);
    renderList();
    mgrSetState("Синхронизировано", "ok");
  } catch (e) {
    mgrSetState(e.message, "err");
  }
}

async function saveCurrent() {
  const url = els.url.value.trim();
  if (!url) {
    showStatus("error", "Сначала введи URL подписки в поле выше.");
    return;
  }
  let defName = "";
  try {
    defName = new URL(url).hostname;
  } catch (e) {}
  const name = prompt("Название подписки:", defName);
  if (name === null) return;
  mgrSetState("Сохранение…");
  try {
    await mgr.store.add({ name: name.trim() || defName || "подписка", url, mode: els.mode.value });
    renderList();
    mgrSetState("Синхронизировано", "ok");
  } catch (e) {
    mgrSetState(e.message, "err");
  }
}

async function login(token) {
  mgr.el.loginBtn.disabled = true;
  mgrSetState("Подключение…");
  try {
    const store = new GistStore(token);
    await store.init();
    mgr.store = store;
    localStorage.setItem(LS_TOKEN, token);
    mgr.el.login.classList.add("hidden");
    mgr.el.panel.classList.remove("hidden");
    renderList();
    mgrSetState("Синхронизировано", "ok");
  } catch (e) {
    mgrSetState(e.message, "err");
    localStorage.removeItem(LS_GISTID);
  } finally {
    mgr.el.loginBtn.disabled = false;
  }
}

function logout() {
  localStorage.removeItem(LS_TOKEN);
  localStorage.removeItem(LS_GISTID);
  mgr.store = null;
  mgr.el.token.value = "";
  mgr.el.panel.classList.add("hidden");
  mgr.el.login.classList.remove("hidden");
  mgrSetState("");
}

// События
mgr.el.loginBtn.addEventListener("click", () => {
  const t = mgr.el.token.value.trim();
  if (!t) {
    mgrSetState("Введите токен", "err");
    return;
  }
  login(t);
});
mgr.el.token.addEventListener("keydown", (e) => {
  if (e.key === "Enter") mgr.el.loginBtn.click();
});
mgr.el.saveCurrent.addEventListener("click", saveCurrent);
mgr.el.refreshAll.addEventListener("click", async () => {
  if (!mgr.store) return;
  mgrSetState("Обновление…");
  try {
    await mgr.store.init();
    renderList();
    mgrSetState("Синхронизировано", "ok");
  } catch (e) {
    mgrSetState(e.message, "err");
  }
});
mgr.el.logout.addEventListener("click", logout);

// Авто-вход, если токен уже сохранён в этом браузере.
(function autoLogin() {
  const t = localStorage.getItem(LS_TOKEN);
  if (t) {
    mgr.el.token.value = t;
    login(t);
  }
})();
