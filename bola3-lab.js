/**
 * BOLA Lab 3 — CloudVault API (multi-tenant SaaS, advanced BOLA / IDOR).
 */

const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const path = require("path");
const { OPEN_ACCESS } = require("./lab-config");

const BOLA3_PASSWORD = process.env.BOLA3_PASSWORD || "portfolio-demo-only";
const BOLA3_COOKIE = "bola3auth";

const ORGS = [
  { id: 1, slug: "acme-corp", name: "Acme Corp" },
  { id: 2, slug: "rival-inc", name: "Rival Inc" },
];

const USERS = [
  { id: 1, username: "sarah", role: "member", orgId: 1, name: "Sarah Chen", token: "DEMO_ONLY_12" },
  { id: 2, username: "mike", role: "member", orgId: 1, name: "Mike Ross", token: "DEMO_ONLY_13" },
  { id: 3, username: "rival", role: "member", orgId: 2, name: "Alex Rival", token: "DEMO_ONLY_14" },
  { id: 4, username: "contractor", role: "contractor", orgId: null, name: "External Contractor", token: "DEMO_ONLY_15" },
  { id: 5, username: "admin", role: "admin", orgId: 1, name: "CloudVault Admin", token: "DEMO_ONLY_16" },
];

const DEFAULT_DOCUMENTS = [
  {
    uuid: "d7a1b2c3-0001-4ac0-8001-000000000101",
    orgId: 1,
    ownerId: 1,
    workspaceId: 801,
    title: "Q3 Roadmap — Acme",
    classification: "internal",
    body: "План релизов CloudVault integration.",
  },
  {
    uuid: "d7a1b2c3-0002-4ac0-8001-000000000102",
    orgId: 1,
    ownerId: 2,
    workspaceId: 801,
    title: "HR Review — confidential",
    classification: "confidential",
    body: "FLAG{BOLA_CLOUDVAULT_DOC_LEAK} — зарплатная вилка инженеров Acme (Mike only).",
  },
  {
    uuid: "d7a1b2c3-0003-4ac0-8001-000000000103",
    orgId: 1,
    ownerId: 1,
    workspaceId: 801,
    title: "M&A Draft — restricted",
    classification: "restricted",
    body: "Черновик поглощения Rival Inc. Не распространять.",
  },
  {
    uuid: "d7a1b2c3-0004-4ac0-8001-000000000201",
    orgId: 2,
    ownerId: 3,
    workspaceId: 802,
    title: "Rival pricing strategy",
    classification: "secret",
    body: "FLAG{BOLA_CLOUDVAULT_CROSS_TENANT} — прайс Rival Inc, другой tenant.",
  },
];

const DEFAULT_WORKSPACES = [
  { id: 801, orgId: 1, name: "Acme Engineering", memberIds: [1, 2, 5] },
  { id: 802, orgId: 2, name: "Rival Sales", memberIds: [3] },
];

const DEFAULT_SHARES = [
  {
    code: "preview-acme-mna-7k2",
    docUuid: "d7a1b2c3-0003-4ac0-8001-000000000103",
    label: "M&A preview link (leaks uuid in response)",
  },
  {
    code: "ext-contractor-read",
    docUuid: "d7a1b2c3-0001-4ac0-8001-000000000101",
    label: "Contractor read-only",
  },
];

const DEFAULT_API_KEYS = [
  {
    id: 901,
    ownerId: 2,
    orgId: 1,
    name: "Mike CI pipeline",
    secret: "DEMO_ONLY_17",
    scopes: ["documents:read"],
  },
  {
    id: 902,
    ownerId: 3,
    orgId: 2,
    name: "Rival sync",
    secret: "DEMO_ONLY_18",
    scopes: ["documents:read", "export"],
  },
];

const DEFAULT_AUDIT_EVENTS = [
  {
    id: 501,
    orgId: 1,
    actor: "admin",
    action: "DOC_EXPORT",
    detail: "Bulk export orgId=1 by admin",
    at: "2026-06-10T08:00:00Z",
  },
  {
    id: 502,
    orgId: 1,
    actor: "system",
    action: "POLICY_VIOLATION",
    detail: "FLAG{BOLA_CLOUDVAULT_AUDIT_EVENT} — cross-tenant access attempt blocked in WAF but logged here",
    at: "2026-06-11T14:22:00Z",
  },
  {
    id: 503,
    orgId: 2,
    actor: "rival",
    action: "SHARE_CREATED",
    detail: "Public share for pricing doc",
    at: "2026-06-12T09:00:00Z",
  },
];

let documents = DEFAULT_DOCUMENTS.map((d) => ({ ...d }));
let workspaces = DEFAULT_WORKSPACES.map((w) => ({ ...w, memberIds: [...w.memberIds] }));
let shares = DEFAULT_SHARES.map((s) => ({ ...s }));
let apiKeys = DEFAULT_API_KEYS.map((k) => ({ ...k }));
let auditEvents = DEFAULT_AUDIT_EVENTS.map((e) => ({ ...e }));
const sessions = new Map();

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";").map((s) => s.trim())) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq) === name) return decodeURIComponent(part.slice(eq + 1));
  }
  return null;
}

function setBola3Auth(res) {
  res.setHeader("Set-Cookie", `${BOLA3_COOKIE}=1; Path=/bola3; HttpOnly; SameSite=Lax`);
}

function clearBola3Auth(res) {
  res.setHeader("Set-Cookie", `${BOLA3_COOKIE}=; Path=/bola3; Max-Age=0; HttpOnly`);
}

function isBola3Authed(req) {
  return getCookie(req, BOLA3_COOKIE) === "1";
}

function gateBola3(req, res, next) {
  if (OPEN_ACCESS || isBola3Authed(req)) return next();
  res.redirect("/bola3/login");
}

function resetBola3Data() {
  documents = DEFAULT_DOCUMENTS.map((d) => ({ ...d }));
  workspaces = DEFAULT_WORKSPACES.map((w) => ({ ...w, memberIds: [...w.memberIds] }));
  shares = DEFAULT_SHARES.map((s) => ({ ...s }));
  apiKeys = DEFAULT_API_KEYS.map((k) => ({ ...k }));
  auditEvents = DEFAULT_AUDIT_EVENTS.map((e) => ({ ...e }));
}

function createSession(user) {
  const accessToken = `cv_${user.id}_${crypto.randomBytes(12).toString("hex")}`;
  sessions.set(accessToken, { userId: user.id, at: Date.now() });
  return accessToken;
}

function findUserByToken(token) {
  if (!token) return null;
  const sess = sessions.get(token);
  if (sess) return USERS.find((u) => u.id === sess.userId) || null;
  return USERS.find((u) => u.token === token) || null;
}

function publicUser(user) {
  const { token, ...rest } = user;
  return rest;
}

function apiAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  const user = findUserByToken(match ? match[1].trim() : "");
  if (!user) {
    return res.status(401).json({
      error: "Unauthorized",
      hint: "POST /auth/login → Authorization: Bearer <accessToken>",
    });
  }
  req.user = user;
  next();
}

function effectiveOrgId(req) {
  const hdr = Number(req.headers["x-organization-id"]);
  if (hdr) return hdr;
  return req.user.orgId;
}

function renderBola3Login(escapeHtml, err) {
  const errHtml = err ? '<p class="practice-login__err">Неверный пароль</p>' : "";
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CloudVault BOLA — вход</title>
  <link rel="stylesheet" href="/style.css">
  <link rel="stylesheet" href="/bola.css">
</head>
<body>
  <header class="site-header">
    <p class="site-header__brand"><a href="/">BOLA Lab</a></p>
    <h1>CloudVault API</h1>
    <p class="subtitle">Доступ по паролю</p>
  </header>
  <main>
    <section class="practice-login">
      <p>BOLA Lab 3 — multi-tenant SaaS. Пароль выдаёт преподаватель.</p>
      ${errHtml}
      <form method="POST" action="/bola3/login">
        <label>Пароль <input type="password" name="password" autocomplete="current-password" required></label>
        <button type="submit">Войти</button>
      </form>
      <p style="margin-top:1rem"><a href="/bola2">← BOLA 2 (PayFlow)</a> · <a href="/bola">BOLA 1</a></p>
    </section>
  </main>
</body>
</html>`;
}

function renderBola3Home(escapeHtml) {
  const rows = USERS.map(
    (u) =>
      `<tr><td><code>${escapeHtml(u.username)}</code></td><td>${escapeHtml(u.role)}</td><td>${u.orgId ?? "—"}</td><td>${u.id}</td></tr>`
  ).join("");

  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BOLA Lab 3 — CloudVault API</title>
  <link rel="stylesheet" href="/style.css">
  <link rel="stylesheet" href="/bola.css">
</head>
<body>
  <header class="site-header">
    <p class="site-header__brand"><a href="/">BOLA Lab</a></p>
    <h1>CloudVault API</h1>
    <p class="subtitle">Multi-tenant · UUID · advanced BOLA</p>
    <nav class="nav" aria-label="Меню">
      <a href="/" class="nav__link">Главная</a>
      <a href="/bola" class="nav__link">BOLA 1</a>
      <a href="/bola2" class="nav__link">BOLA 2</a>
      <a href="/bola3" class="nav__link nav__link--active">BOLA 3</a>
      <a href="/bola3/docs" class="nav__link">Swagger</a>
      <a href="/bola3/guide" class="nav__link">Методичка</a>
    </nav>
  </header>

  <main>
    <section class="bola-card">
      <span class="badge badge--danger">Режим: уязвимый API</span>
      <h2>Чем сложнее PayFlow (BOLA 2)?</h2>
      <ul class="bola-list">
        <li><strong>Multi-tenant</strong> — orgId, чужой tenant (Rival Inc)</li>
        <li><strong>UUID</strong> — документы не по порядковому id; разведка через share / org / batch</li>
        <li><strong>Заголовок X-Organization-Id</strong> — подмена tenant в summary</li>
        <li><strong>POST query / batch-fetch</strong> — массовая утечка по фильтрам и списку uuid</li>
        <li><strong>Public share</strong> — без Bearer, но выдаёт uuid документа</li>
        <li><strong>Support header</strong> — X-Impersonate-User для «службы поддержки»</li>
        <li><strong>Audit trap 2.0</strong> — список закрыт, event по id открыт</li>
        <li><strong>API keys</strong> — секреты чужих ключей по id</li>
        <li><strong>Transfer / PATCH</strong> — write BOLA на чужих документах</li>
      </ul>
      <p>API: <code>http://localhost:3847/bola3/api/v1</code> · <a href="/bola3/docs">Swagger</a></p>
    </section>

    <section class="bola-card">
      <h2>Тестовые пользователи</h2>
      <p>Это логины для <code>POST /auth/login</code>, не Bearer-токены. Пароль у всех один — пароль лаборатории. В Authorize идёт <code>accessToken</code> из ответа login.</p>
      <table class="bola-table">
        <thead><tr><th>Логин</th><th>Роль</th><th>Org</th><th>id</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>

    <section class="bola-card">
      <h2>Задания (работайте как sarah)</h2>
      <p class="subtitle">15 заданий — цели ниже, эндпоинты ищите в <a href="/bola3/docs">Swagger</a>. Подробнее: <a href="/bola3/guide">методичка</a>.</p>
      <ol class="bola-list">
        <li><strong>Найдите</strong> свой профиль после входа — orgId, id, роль</li>
        <li><strong>Найдите</strong> список «моих» документов — сколько? почему не все в org?</li>
        <li><strong>Сделайте</strong> cross-tenant: документы организации Rival (не Acme)</li>
        <li><strong>Найдите</strong> uuid документа Mike → <strong>прочитайте</strong> полный текст и флаг</li>
        <li><strong>Откройте</strong> public share <code>preview-acme-mna-7k2</code> без Bearer — что утекло?</li>
        <li><strong>Получите</strong> полный restricted M&A по uuid из разведки</li>
        <li><strong>Сделайте</strong> summary с tenant Rival через заголовок (остаясь sarah)</li>
        <li><strong>Найдите</strong> POST-фильтр → все <code>confidential</code> в org 1</li>
        <li><strong>Batch-fetch:</strong> два uuid одним запросом (Acme + cross-tenant)</li>
        <li><strong>Roster</strong> workspace Rival — кто в команде?</li>
        <li><strong>Vault export</strong> пользователя rival — что слилось?</li>
        <li><strong>Audit:</strong> список закрыт → доберитесь до события <strong>502</strong></li>
        <li><strong>Secret</strong> чужого API key Mike</li>
        <li><strong>PUT</strong> — измените title чужого документа</li>
        <li><strong>Transfer</strong> — заберите владение документом Mike</li>
      </ol>
    </section>

    <section class="bola-card">
      <form method="POST" action="/bola3/reset" onsubmit="return confirm('Сбросить CloudVault?')">
        <button type="submit" class="btn btn--danger">Сбросить данные</button>
      </form>
      <form class="practice-logout" method="POST" action="/bola3/logout" style="margin-top:0.75rem">
        <button type="submit" class="btn btn--danger">Выйти</button>
      </form>
    </section>
  </main>
  <footer><p>Учебный пример. Только localhost.</p></footer>
</body>
</html>`;
}

function renderSwagger3() {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>CloudVault — Swagger</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css">
  <link rel="stylesheet" href="/bola.css">
</head>
<body class="bola-swagger-body">
  <header class="bola-swagger-bar">
    <a href="/bola3">← CloudVault Lab</a>
    <span>CloudVault API — Swagger UI</span>
    <a href="/bola3/openapi.yaml">openapi.yaml</a>
  </header>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: "/bola3/openapi.yaml",
      dom_id: "#swagger-ui",
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis],
      layout: "BaseLayout",
      tryItOutEnabled: true,
      persistAuthorization: true,
    });
  </script>
</body>
</html>`;
}

function mountBola3(app, { escapeHtml }) {
  const publicApi = express.Router();
  publicApi.use(express.json());

  publicApi.post("/auth/login", (req, res) => {
    const username = String(req.body.username || "").trim();
    const password = req.body.password || "";
    if (password !== BOLA3_PASSWORD) {
      return res.status(401).json({
        error: "Invalid credentials",
        hint: "password — пароль лаборатории от преподавателя",
      });
    }
    const user = USERS.find((u) => u.username === username);
    if (!user) {
      return res.status(401).json({
        error: "Invalid credentials",
        hint: "username: sarah, mike, rival, contractor, admin",
      });
    }
    const accessToken = createSession(user);
    res.json({
      accessToken,
      tokenType: "Bearer",
      expiresIn: 7200,
      user: publicUser(user),
    });
  });

  publicApi.get("/shares/:shareCode", (req, res) => {
    const share = shares.find((s) => s.code === req.params.shareCode);
    if (!share) return res.status(404).json({ error: "Share not found" });
    const doc = documents.find((d) => d.uuid === share.docUuid);
    if (!doc) return res.status(404).json({ error: "Document missing" });
    res.json({
      share: { code: share.code, label: share.label },
      docUuid: doc.uuid,
      title: doc.title,
      classification: doc.classification,
      preview: doc.body.slice(0, 120) + (doc.body.length > 120 ? "…" : ""),
      hint: "Полный текст — GET /documents/{uuid} с Bearer (BOLA)",
    });
  });

  const api = express.Router();
  api.use(express.json());
  api.use(apiAuth);

  api.get("/", (req, res) => {
    res.json({
      name: "CloudVault API",
      version: "v1",
      lab: "BOLA 3",
      user: publicUser(req.user),
      docs: "/bola3/docs",
      challenges: 15,
      harderThan: "PayFlow BOLA 2 — multi-tenant, UUID, headers, batch, shares",
    });
  });

  api.get("/me", (req, res) => {
    res.json(publicUser(req.user));
  });

  api.get("/me/documents", (req, res) => {
    const list = documents.filter((d) => d.ownerId === req.user.id);
    res.json({ documents: list, count: list.length });
  });

  api.get("/me/summary", (req, res) => {
    const orgId = effectiveOrgId(req);
    const org = ORGS.find((o) => o.id === orgId);
    const orgDocs = documents.filter((d) => d.orgId === orgId);
    res.json({
      orgId,
      orgName: org ? org.name : null,
      documentCount: orgDocs.length,
      classifications: orgDocs.reduce((acc, d) => {
        acc[d.classification] = (acc[d.classification] || 0) + 1;
        return acc;
      }, {}),
      note: orgId !== req.user.orgId ? "BOLA — X-Organization-Id switched tenant context" : null,
    });
  });

  api.get("/organizations/:orgId/documents", (req, res) => {
    const orgId = Number(req.params.orgId);
    const list = documents.filter((d) => d.orgId === orgId);
    res.json({ orgId, documents: list, count: list.length });
  });

  api.get("/documents/:docUuid", (req, res) => {
    const doc = documents.find((d) => d.uuid === req.params.docUuid);
    if (!doc) return res.status(404).json({ error: "Document not found" });
    res.json(doc);
  });

  api.put("/documents/:docUuid", (req, res) => {
    const doc = documents.find((d) => d.uuid === req.params.docUuid);
    if (!doc) return res.status(404).json({ error: "Document not found" });
    if (req.body.title !== undefined) doc.title = String(req.body.title).slice(0, 200);
    if (req.body.body !== undefined) doc.body = String(req.body.body).slice(0, 4000);
    if (req.body.classification !== undefined) {
      doc.classification = String(req.body.classification).slice(0, 40);
    }
    res.json(doc);
  });

  api.post("/documents/:docUuid/transfer", (req, res) => {
    const doc = documents.find((d) => d.uuid === req.params.docUuid);
    if (!doc) return res.status(404).json({ error: "Document not found" });
    const newOwnerId = Number(req.body.newOwnerId);
    const target = USERS.find((u) => u.id === newOwnerId);
    if (!target) return res.status(400).json({ error: "newOwnerId invalid" });
    doc.ownerId = newOwnerId;
    res.json({ transferred: true, document: doc });
  });

  api.post("/documents/query", (req, res) => {
    const { orgId, ownerId, classification, workspaceId } = req.body || {};
    let list = [...documents];
    if (orgId) list = list.filter((d) => d.orgId === Number(orgId));
    if (ownerId) list = list.filter((d) => d.ownerId === Number(ownerId));
    if (classification) list = list.filter((d) => d.classification === classification);
    if (workspaceId) list = list.filter((d) => d.workspaceId === Number(workspaceId));
    res.json({ documents: list, count: list.length });
  });

  api.post("/documents/batch-fetch", (req, res) => {
    const uuids = Array.isArray(req.body.uuids) ? req.body.uuids.map(String) : [];
    const list = uuids
      .map((uuid) => documents.find((d) => d.uuid === uuid))
      .filter(Boolean);
    res.json({ documents: list, requested: uuids.length, found: list.length });
  });

  api.get("/workspaces/:workspaceId/roster", (req, res) => {
    const ws = workspaces.find((w) => w.id === Number(req.params.workspaceId));
    if (!ws) return res.status(404).json({ error: "Workspace not found" });
    const members = ws.memberIds
      .map((id) => USERS.find((u) => u.id === id))
      .filter(Boolean)
      .map(publicUser);
    res.json({ workspaceId: ws.id, orgId: ws.orgId, name: ws.name, members });
  });

  api.get("/users/:userId/vault-export", (req, res) => {
    const userId = Number(req.params.userId);
    const user = USERS.find((u) => u.id === userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({
      user: publicUser(user),
      documents: documents.filter((d) => d.ownerId === userId),
      apiKeys: apiKeys.filter((k) => k.ownerId === userId),
      workspaces: workspaces.filter((w) => w.memberIds.includes(userId)),
    });
  });

  api.get("/support/session", (req, res) => {
    const imp = Number(req.headers["x-impersonate-user"]);
    if (!imp) {
      return res.status(400).json({
        error: "X-Impersonate-User header required",
        hint: "Support portal — попробуйте id другого пользователя (BOLA)",
      });
    }
    const target = USERS.find((u) => u.id === imp);
    if (!target) return res.status(404).json({ error: "User not found" });
    res.json({
      supportMode: true,
      actingAs: publicUser(target),
      documents: documents.filter((d) => d.ownerId === target.id),
    });
  });

  api.get("/api-keys/:keyId", (req, res) => {
    const key = apiKeys.find((k) => k.id === Number(req.params.keyId));
    if (!key) return res.status(404).json({ error: "API key not found" });
    res.json(key);
  });

  api.get("/audit/events", (req, res) => {
    if (req.user.role !== "admin" && req.user.role !== "auditor") {
      return res.status(403).json({
        error: "Forbidden",
        hint: "Список только admin. Попробуйте GET /audit/events/{id} — отдельные события…",
      });
    }
    res.json({ events: auditEvents, count: auditEvents.length });
  });

  api.get("/audit/events/:eventId", (req, res) => {
    const ev = auditEvents.find((e) => e.id === Number(req.params.eventId));
    if (!ev) return res.status(404).json({ error: "Event not found" });
    res.json(ev);
  });

  app.get("/bola3/login", (req, res) => {
    if (OPEN_ACCESS || isBola3Authed(req)) return res.redirect("/bola3");
    res.send(renderBola3Login(escapeHtml, Boolean(req.query.err)));
  });

  app.post("/bola3/login", express.json(), (req, res) => {
    if ((req.body.password || "") === BOLA3_PASSWORD) {
      setBola3Auth(res);
      if (req.is("json")) {
        return res.json({ ok: true, message: "Cookie bola3auth установлен." });
      }
      return res.redirect("/bola3");
    }
    if (req.is("json")) {
      return res.status(401).json({ error: "Invalid password", hint: "password: portfolio-demo-only" });
    }
    res.redirect("/bola3/login?err=1");
  });

  app.post("/bola3/logout", (req, res) => {
    clearBola3Auth(res);
    res.redirect("/bola3/login");
  });

  app.get("/bola3", gateBola3, (req, res) => {
    res.send(renderBola3Home(escapeHtml));
  });

  app.get("/bola3/docs", gateBola3, (req, res) => {
    res.send(renderSwagger3());
  });

  app.get("/bola3/openapi.yaml", gateBola3, (req, res) => {
    res.type("text/yaml").send(fs.readFileSync(path.join(__dirname, "DOCS", "bola3-openapi.yaml"), "utf8"));
  });

  app.get("/bola3/guide", gateBola3, (req, res) => {
    const md = fs.readFileSync(path.join(__dirname, "DOCS", "bola3.txt"), "utf8");
    const body = md.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    res.send(`<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>BOLA3</title>
      <link rel="stylesheet" href="/style.css"><link rel="stylesheet" href="/bola.css"></head>
      <body><p class="site-header__brand"><a href="/bola3">← CloudVault</a></p>
      <pre class="bola-pre" style="white-space:pre-wrap">${body}</pre></body></html>`);
  });

  app.post("/bola3/reset", gateBola3, (req, res) => {
    resetBola3Data();
    res.redirect("/bola3");
  });

  app.use("/bola3/api/v1", publicApi);
  app.use("/bola3/api/v1", api);
}

module.exports = { mountBola3, resetBola3Data, USERS, BOLA3_PASSWORD };
