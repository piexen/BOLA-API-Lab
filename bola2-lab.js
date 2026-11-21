/**
 * BOLA Lab 2 — PayFlow API (финтех, усложнённые сценарии BOLA).
 */

const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const path = require("path");
const { OPEN_ACCESS } = require("./lab-config");

const BOLA2_PASSWORD = process.env.BOLA2_PASSWORD || "portfolio-demo-only";
const BOLA2_COOKIE = "bola2auth";

const USERS = [
  { id: 1, username: "alice", role: "customer", email: "alice@mail.test", kycLevel: "verified", token: "DEMO_ONLY_06" },
  { id: 2, username: "bob", role: "customer", email: "bob@mail.test", kycLevel: "verified", token: "DEMO_ONLY_07" },
  { id: 3, username: "cafe24", role: "merchant", email: "pay@cafe24.test", kycLevel: "business", token: "DEMO_ONLY_08" },
  { id: 4, username: "techshop", role: "merchant", email: "billing@techshop.test", kycLevel: "business", token: "DEMO_ONLY_09" },
  { id: 5, username: "auditor", role: "auditor", email: "audit@payflow.test", kycLevel: "internal", token: "DEMO_ONLY_10" },
  { id: 6, username: "admin", role: "admin", email: "admin@payflow.test", kycLevel: "internal", token: "DEMO_ONLY_11" },
];

const DEFAULT_WALLETS = [
  { id: 501, ref: "WLT-alice9k2m", ownerId: 1, currency: "EUR", balance: 1250.0, label: "Основной" },
  { id: 502, ref: "WLT-bob8f2a1", ownerId: 2, currency: "EUR", balance: 890.5, label: "Личный" },
  { id: 503, ref: "WLT-cafe44x1", ownerId: 3, currency: "EUR", balance: 15420.0, label: "Выручка Cafe24" },
  { id: 504, ref: "WLT-tech7p0q", ownerId: 4, currency: "EUR", balance: 8832.1, label: "TechShop" },
];

const DEFAULT_TRANSACTIONS = [
  {
    id: 9001,
    fromWalletId: 501,
    toWalletId: 503,
    amount: 450,
    description: "Подписка на кофе",
    internalNote: "merchant fee 2.1%",
    createdAt: "2026-05-10T08:00:00Z",
  },
  {
    id: 9002,
    fromWalletId: 502,
    toWalletId: 504,
    amount: 120,
    description: "Заказ #8812",
    internalNote: "FLAG{BOLA_PAYFLOW_INTERNAL_NOTE} — конфиденциальная служебная пометка",
    createdAt: "2026-05-11T12:30:00Z",
  },
  {
    id: 9003,
    fromWalletId: 501,
    toWalletId: 502,
    amount: 200,
    description: "Возврат долга",
    internalNote: "p2p settlement, no merchant fee",
    createdAt: "2026-05-15T18:00:00Z",
  },
  {
    id: 9004,
    fromWalletId: 504,
    toWalletId: 503,
    amount: 5000,
    description: "B2B расчёт",
    internalNote: "contract ref: NDA-2026-TECH-CAFE",
    createdAt: "2026-05-20T09:00:00Z",
  },
];

const DEFAULT_CARDS = [
  { id: 701, walletId: 501, brand: "Visa", last4: "4242", pan: "4111 1111 1111 4242", exp: "09/28", cvv: "123" },
  { id: 702, walletId: 502, brand: "Mastercard", last4: "5555", pan: "5500 0000 0000 5555", exp: "03/27", cvv: "456" },
  { id: 703, walletId: 504, brand: "Mir", last4: "9012", pan: "2202 2020 2020 9012", exp: "11/29", cvv: "789" },
];

const DEFAULT_INVOICES = [
  {
    id: 601,
    ownerId: 2,
    amount: 5000,
    status: "pending",
    items: ["Корпоративная лицензия PayFlow Pro", "Скидка партнёра -10%"],
  },
  {
    id: 602,
    ownerId: 1,
    amount: 120,
    status: "paid",
    items: ["Доставка еды"],
  },
  {
    id: 603,
    ownerId: 4,
    amount: 42000,
    status: "paid",
    items: ["Оптовая поставка SSD", "FLAG{BOLA_PAYFLOW_INVOICE_LEAK}"],
  },
];

const DEFAULT_AUDIT_LOGS = [
  { id: 1, actor: "admin", action: "LOGIN", detail: "Admin session from 10.0.0.5", at: "2026-06-01T08:00:00Z" },
  { id: 2, actor: "system", action: "WALLET_FREEZE", detail: "Wallet 502 flagged for review (false positive)", at: "2026-06-02T11:00:00Z" },
  {
    id: 3,
    actor: "admin",
    action: "MANUAL_ADJUST",
    detail: "FLAG{BOLA_PAYFLOW_AUDIT_BYPASS} — ручная корректировка баланса wallet 502 +10000 EUR",
    at: "2026-06-03T15:30:00Z",
  },
  { id: 4, actor: "auditor", action: "EXPORT", detail: "Full export userId=4 requested", at: "2026-06-04T09:00:00Z" },
];

let wallets = DEFAULT_WALLETS.map((w) => ({ ...w }));
let transactions = DEFAULT_TRANSACTIONS.map((t) => ({ ...t }));
let cards = DEFAULT_CARDS.map((c) => ({ ...c }));
let invoices = DEFAULT_INVOICES.map((i) => ({ ...i }));
let auditLogs = DEFAULT_AUDIT_LOGS.map((l) => ({ ...l }));
let nextTxId = 9010;
let nextInvoiceId = 610;
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

function setBola2Auth(res) {
  res.setHeader("Set-Cookie", `${BOLA2_COOKIE}=1; Path=/bola2; HttpOnly; SameSite=Lax`);
}

function clearBola2Auth(res) {
  res.setHeader("Set-Cookie", `${BOLA2_COOKIE}=; Path=/bola2; Max-Age=0; HttpOnly`);
}

function isBola2Authed(req) {
  return getCookie(req, BOLA2_COOKIE) === "1";
}

function gateBola2(req, res, next) {
  if (OPEN_ACCESS || isBola2Authed(req)) return next();
  res.redirect("/bola2/login");
}

function resetBola2Data() {
  wallets = DEFAULT_WALLETS.map((w) => ({ ...w }));
  transactions = DEFAULT_TRANSACTIONS.map((t) => ({ ...t }));
  cards = DEFAULT_CARDS.map((c) => ({ ...c }));
  invoices = DEFAULT_INVOICES.map((i) => ({ ...i }));
  auditLogs = DEFAULT_AUDIT_LOGS.map((l) => ({ ...l }));
  nextTxId = 9010;
  nextInvoiceId = 610;
}

function createSession(user) {
  const accessToken = `pf_${user.id}_${crypto.randomBytes(12).toString("hex")}`;
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
      hint: "Сначала POST /auth/login (username + пароль лабы), затем Authorization: Bearer <accessToken>",
    });
  }
  req.user = user;
  next();
}

function walletOwnerId(walletId) {
  const w = wallets.find((x) => x.id === walletId);
  return w ? w.ownerId : null;
}

function transactionsForUser(userId) {
  const userWalletIds = wallets.filter((w) => w.ownerId === userId).map((w) => w.id);
  return transactions.filter(
    (t) => userWalletIds.includes(t.fromWalletId) || userWalletIds.includes(t.toWalletId)
  );
}

function renderBola2Login(escapeHtml, err) {
  const errHtml = err ? '<p class="practice-login__err">Неверный пароль</p>' : "";
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PayFlow BOLA — вход</title>
  <link rel="stylesheet" href="/style.css">
  <link rel="stylesheet" href="/bola.css">
</head>
<body>
  <header class="site-header">
    <p class="site-header__brand"><a href="/">BOLA Lab</a></p>
    <h1>PayFlow API</h1>
    <p class="subtitle">Доступ по паролю</p>
  </header>
  <main>
    <section class="practice-login">
      <p>BOLA Lab 2 — финтех-сценарии. Пароль выдаёт преподаватель.</p>
      ${errHtml}
      <form method="POST" action="/bola2/login">
        <label>Пароль <input type="password" name="password" autocomplete="current-password" required></label>
        <button type="submit">Войти</button>
      </form>
      <p style="margin-top:1rem"><a href="/bola">← BOLA Lab 1 (MediNotes)</a> · <a href="/bola3">BOLA 3 (CloudVault) →</a></p>
    </section>
  </main>
</body>
</html>`;
}

function renderBola2Home(escapeHtml) {
  const rows = USERS.map(
    (u) =>
      `<tr><td><code>${escapeHtml(u.username)}</code></td><td>${escapeHtml(u.role)}</td><td>${u.id}</td></tr>`
  ).join("");

  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BOLA Lab 2 — PayFlow API</title>
  <link rel="stylesheet" href="/style.css">
  <link rel="stylesheet" href="/bola.css">
</head>
<body>
  <header class="site-header">
    <p class="site-header__brand"><a href="/">BOLA Lab</a></p>
    <h1>PayFlow API</h1>
    <p class="subtitle">Финтех · усложнённые BOLA / IDOR</p>
    <nav class="nav" aria-label="Меню">
      <a href="/" class="nav__link">Главная</a>
      <a href="/bola" class="nav__link">BOLA 1</a>
      <a href="/bola2" class="nav__link nav__link--active">BOLA 2</a>
      <a href="/bola3" class="nav__link">BOLA 3</a>
      <a href="/bola2/docs" class="nav__link">Swagger</a>
      <a href="/bola2/guide" class="nav__link">Методичка</a>
    </nav>
  </header>

  <main>
    <section class="bola-card">
      <span class="badge badge--danger">Режим: уязвимый API</span>
      <h2>Чем сложнее MediNotes?</h2>
      <ul class="bola-list">
        <li><strong>Ложная безопасность</strong> — «свои» списки фильтруют, прямой доступ по id — нет</li>
        <li><strong>Query override</strong> — подмена объекта через параметры запроса</li>
        <li><strong>POST search</strong> — чужие данные через тело запроса</li>
        <li><strong>Переводы</strong> — списание без проверки владельца кошелька</li>
        <li><strong>Карты</strong> — полные реквизиты по id</li>
        <li><strong>Audit trap</strong> — список закрыт, отдельная запись может быть открыта</li>
        <li><strong>PATCH</strong> — смена статуса чужого документа</li>
      </ul>
      <p>Документация API: <a href="/bola2/docs">Swagger UI</a></p>
    </section>

    <section class="bola-card">
      <h2>Тестовые пользователи</h2>
      <p>Это логины для <code>POST /auth/login</code>, не Bearer-токены. Пароль у всех один — пароль лаборатории. В Authorize идёт <code>accessToken</code> из ответа login.</p>
      <table class="bola-table">
        <thead><tr><th>Логин</th><th>Роль</th><th>id</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>

    <section class="bola-card">
      <h2>Задания (для alice)</h2>
      <p class="subtitle">Эндпоинты ищите в <a href="/bola2/docs">Swagger</a>. Работайте от имени alice.</p>
      <ol class="bola-list">
        <li>Войти в API и проверить, сколько своих кошельков у alice</li>
        <li>Узнать баланс пользователя Bob</li>
        <li>Получить профиль Bob, оставаясь под учёткой alice</li>
        <li>Найти флаг в служебной пометке чужой транзакции</li>
        <li>Обойти ограничение на список аудит-логов — добраться до отдельной записи</li>
        <li>Перевести деньги с кошелька Bob на свой</li>
        <li>Получить все транзакции Bob через поиск</li>
        <li>Найти кошелёк Bob по альтернативному идентификатору (ref)</li>
        <li>Найти чужой инвойс и флаг в позициях счёта</li>
        <li>Получить полные реквизиты чужой карты (PAN/CVV)</li>
        <li>Скачать полный экспорт данных пользователя Bob</li>
        <li>Отменить чужой неоплаченный инвойс</li>
      </ol>
    </section>

    <section class="bola-card">
      <h2>Как работать</h2>
      <p>Откройте <a href="/bola2/docs">Swagger UI</a> → <strong>POST /auth/login</strong> (username: alice, пароль лаборатории) → скопируйте <code>accessToken</code> → кнопка <strong>Authorize</strong> → <code>Bearer &lt;token&gt;</code>.</p>
      <p>Дальше все задания — через Try it out в Swagger.</p>
    </section>

    <section class="bola-card">
      <form method="POST" action="/bola2/reset" onsubmit="return confirm('Сбросить PayFlow?')">
        <button type="submit" class="btn btn--danger">Сбросить данные</button>
      </form>
      <form class="practice-logout" method="POST" action="/bola2/logout" style="margin-top:0.75rem">
        <button type="submit" class="btn btn--danger">Выйти</button>
      </form>
    </section>
  </main>
  <footer><p>Учебный пример. Только localhost.</p></footer>
</body>
</html>`;
}

function renderSwagger2() {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>PayFlow — Swagger</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css">
  <link rel="stylesheet" href="/bola.css">
</head>
<body class="bola-swagger-body">
  <header class="bola-swagger-bar">
    <a href="/bola2">← PayFlow Lab</a>
    <span>PayFlow API — Swagger UI</span>
    <a href="/bola2/openapi.yaml">openapi.yaml</a>
  </header>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: "/bola2/openapi.yaml",
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

function mountBola2(app, { escapeHtml }) {
  const publicApi = express.Router();
  publicApi.use(express.json());

  publicApi.post("/auth/login", (req, res) => {
    const username = String(req.body.username || "").trim();
    const password = req.body.password || "";
    if (password !== BOLA2_PASSWORD) {
      return res.status(401).json({
        error: "Invalid credentials",
        hint: "password — пароль лаборатории от преподавателя",
      });
    }
    const user = USERS.find((u) => u.username === username);
    if (!user) {
      return res.status(401).json({
        error: "Invalid credentials",
        hint: "username: alice, bob, cafe24, techshop, auditor, admin",
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

  const api = express.Router();
  api.use(express.json());
  api.use(apiAuth);

  api.get("/", (req, res) => {
    res.json({
      name: "PayFlow API",
      version: "v1",
      lab: "BOLA 2",
      user: publicUser(req.user),
      docs: "/bola2/docs",
      login: "POST /auth/login",
      siblingLab: "/bola",
      challenges: [
        "Вход и свои кошельки",
        "Баланс другого пользователя",
        "Чужой профиль через параметры запроса",
        "Служебное поле чужой транзакции",
        "Audit trap: list vs отдельная запись",
        "Перевод с чужого кошелька",
        "Поиск чужих транзакций в теле POST",
        "Кошелёк по альтернативному ref",
        "Чужой инвойс и флаг",
        "PAN/CVV чужой карты",
        "Экспорт данных пользователя",
        "Отмена чужого инвойса",
      ],
    });
  });

  api.get("/me/profile", (req, res) => {
    const overrideId = Number(req.query.userId);
    if (overrideId) {
      const target = USERS.find((u) => u.id === overrideId);
      if (!target) return res.status(404).json({ error: "User not found" });
      return res.json(publicUser(target));
    }
    res.json(publicUser(req.user));
  });

  api.get("/me/wallets", (req, res) => {
    const list = wallets.filter((w) => w.ownerId === req.user.id);
    res.json({ wallets: list, count: list.length });
  });

  api.get("/wallets/:walletId", (req, res) => {
    const wallet = wallets.find((w) => w.id === Number(req.params.walletId));
    if (!wallet) return res.status(404).json({ error: "Wallet not found" });
    res.json(wallet);
  });

  api.get("/wallets/by-ref/:ref", (req, res) => {
    const wallet = wallets.find((w) => w.ref === req.params.ref);
    if (!wallet) return res.status(404).json({ error: "Wallet not found" });
    res.json(wallet);
  });

  api.get("/wallets/:walletId/transactions", (req, res) => {
    const wid = Number(req.params.walletId);
    if (!wallets.some((w) => w.id === wid)) return res.status(404).json({ error: "Wallet not found" });
    const list = transactions.filter((t) => t.fromWalletId === wid || t.toWalletId === wid);
    res.json({ walletId: wid, transactions: list, count: list.length });
  });

  api.get("/transactions/:transactionId", (req, res) => {
    const tx = transactions.find((t) => t.id === Number(req.params.transactionId));
    if (!tx) return res.status(404).json({ error: "Transaction not found" });
    res.json(tx);
  });

  api.post("/transactions/search", (req, res) => {
    const { userId, walletId, minAmount } = req.body || {};
    let list = [...transactions];
    if (userId) {
      const wids = wallets.filter((w) => w.ownerId === Number(userId)).map((w) => w.id);
      list = list.filter((t) => wids.includes(t.fromWalletId) || wids.includes(t.toWalletId));
    }
    if (walletId) {
      const wid = Number(walletId);
      list = list.filter((t) => t.fromWalletId === wid || t.toWalletId === wid);
    }
    if (minAmount) list = list.filter((t) => t.amount >= Number(minAmount));
    res.json({ transactions: list, count: list.length });
  });

  api.post("/transfers", (req, res) => {
    const fromWalletId = Number(req.body.fromWalletId);
    const toWalletId = Number(req.body.toWalletId);
    const amount = Number(req.body.amount);
    const memo = (req.body.memo || "").slice(0, 200);
    if (!fromWalletId || !toWalletId || !amount || amount <= 0) {
      return res.status(400).json({ error: "fromWalletId, toWalletId, positive amount required" });
    }
    const from = wallets.find((w) => w.id === fromWalletId);
    const to = wallets.find((w) => w.id === toWalletId);
    if (!from || !to) return res.status(404).json({ error: "Wallet not found" });
    if (from.balance < amount) return res.status(400).json({ error: "Insufficient funds" });
    from.balance = Math.round((from.balance - amount) * 100) / 100;
    to.balance = Math.round((to.balance + amount) * 100) / 100;
    const tx = {
      id: nextTxId++,
      fromWalletId,
      toWalletId,
      amount,
      description: memo || "Transfer",
      internalNote: `initiated by user ${req.user.id} (${req.user.username}) — no ownership check on source wallet`,
      createdAt: new Date().toISOString(),
    };
    transactions.push(tx);
    res.status(201).json({ transfer: tx, fromBalance: from.balance, toBalance: to.balance });
  });

  api.get("/cards/:cardId", (req, res) => {
    const card = cards.find((c) => c.id === Number(req.params.cardId));
    if (!card) return res.status(404).json({ error: "Card not found" });
    res.json(card);
  });

  api.delete("/cards/:cardId", (req, res) => {
    const id = Number(req.params.cardId);
    const idx = cards.findIndex((c) => c.id === id);
    if (idx === -1) return res.status(404).json({ error: "Card not found" });
    cards.splice(idx, 1);
    res.json({ deleted: true, id });
  });

  api.get("/invoices", (req, res) => {
    const list = invoices.filter((i) => i.ownerId === req.user.id);
    res.json({ invoices: list, count: list.length });
  });

  api.get("/invoices/:invoiceId", (req, res) => {
    const inv = invoices.find((i) => i.id === Number(req.params.invoiceId));
    if (!inv) return res.status(404).json({ error: "Invoice not found" });
    res.json(inv);
  });

  api.patch("/invoices/:invoiceId/status", (req, res) => {
    const inv = invoices.find((i) => i.id === Number(req.params.invoiceId));
    if (!inv) return res.status(404).json({ error: "Invoice not found" });
    const status = req.body.status;
    if (!["pending", "paid", "cancelled"].includes(status)) {
      return res.status(400).json({ error: "status must be pending, paid, or cancelled" });
    }
    inv.status = status;
    res.json(inv);
  });

  api.get("/users/:userId/export", (req, res) => {
    const userId = Number(req.params.userId);
    const user = USERS.find((u) => u.id === userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    const userWallets = wallets.filter((w) => w.ownerId === userId);
    const wids = userWallets.map((w) => w.id);
    res.json({
      user: publicUser(user),
      wallets: userWallets,
      cards: cards.filter((c) => wids.includes(c.walletId)),
      transactions: transactions.filter((t) => wids.includes(t.fromWalletId) || wids.includes(t.toWalletId)),
      invoices: invoices.filter((i) => i.ownerId === userId),
    });
  });

  api.get("/audit/logs", (req, res) => {
    if (req.user.role !== "auditor" && req.user.role !== "admin") {
      return res.status(403).json({
        error: "Forbidden",
        hint: "Только auditor/admin. Но попробуйте GET /audit/logs/{id} — отдельные записи могут быть открыты…",
      });
    }
    res.json({ logs: auditLogs, count: auditLogs.length });
  });

  api.get("/audit/logs/:logId", (req, res) => {
    const log = auditLogs.find((l) => l.id === Number(req.params.logId));
    if (!log) return res.status(404).json({ error: "Log not found" });
    res.json(log);
  });

  app.get("/bola2/login", (req, res) => {
    if (OPEN_ACCESS || isBola2Authed(req)) return res.redirect("/bola2");
    res.send(renderBola2Login(escapeHtml, Boolean(req.query.err)));
  });

  app.post("/bola2/login", express.json(), (req, res) => {
    const password = req.body.password || "";
    if (password === BOLA2_PASSWORD) {
      setBola2Auth(res);
      if (req.is("json")) {
        return res.json({
          ok: true,
          message: "Вход выполнен. Cookie bola2auth установлен — используйте его в следующих запросах.",
        });
      }
      return res.redirect("/bola2");
    }
    if (req.is("json")) {
      return res.status(401).json({ error: "Invalid password", hint: "password: portfolio-demo-only" });
    }
    res.redirect("/bola2/login?err=1");
  });

  app.post("/bola2/logout", (req, res) => {
    clearBola2Auth(res);
    res.redirect("/bola2/login");
  });

  app.get("/bola2", gateBola2, (req, res) => {
    res.send(renderBola2Home(escapeHtml));
  });

  app.get("/bola2/docs", gateBola2, (req, res) => {
    res.send(renderSwagger2());
  });

  app.get("/bola2/openapi.yaml", gateBola2, (req, res) => {
    res.type("text/yaml").send(fs.readFileSync(path.join(__dirname, "DOCS", "bola2-openapi.yaml"), "utf8"));
  });

  app.get("/bola2/guide", gateBola2, (req, res) => {
    const md = fs.readFileSync(path.join(__dirname, "DOCS", "bola2.txt"), "utf8");
    const body = md.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    res.send(`<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>BOLA2</title>
      <link rel="stylesheet" href="/style.css"><link rel="stylesheet" href="/bola.css"></head>
      <body><p class="site-header__brand"><a href="/bola2">← PayFlow</a></p>
      <pre class="bola-pre" style="white-space:pre-wrap">${body}</pre></body></html>`);
  });

  app.post("/bola2/reset", gateBola2, (req, res) => {
    resetBola2Data();
    res.redirect("/bola2");
  });

  app.use("/bola2/api/v1", publicApi);
  app.use("/bola2/api/v1", api);
}

module.exports = { mountBola2, resetBola2Data, USERS, BOLA2_PASSWORD };
