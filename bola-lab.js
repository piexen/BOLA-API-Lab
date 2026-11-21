/**
 * BOLA Lab — MediNotes API (намеренно уязвимый REST API).
 * Broken Object Level Authorization / IDOR.
 */

const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const path = require("path");
const { OPEN_ACCESS } = require("./lab-config");

const BOLA_PASSWORD = process.env.BOLA_PASSWORD || "portfolio-demo-only";
const BOLA_COOKIE = "bolaauth";

const USERS = [
  { id: 1, username: "dr.ivanov", role: "doctor", name: "Иванов А.П.", token: "DEMO_ONLY_01" },
  { id: 2, username: "dr.petrova", role: "doctor", name: "Петрова М.С.", token: "DEMO_ONLY_02" },
  { id: 3, username: "patient.kozlov", role: "patient", name: "Козлов И.В.", token: "DEMO_ONLY_03" },
  { id: 4, username: "patient.sidorov", role: "patient", name: "Сидоров П.А.", token: "DEMO_ONLY_04" },
  { id: 5, username: "admin", role: "admin", name: "Администратор", token: "DEMO_ONLY_05" },
];

const DEFAULT_NOTES = [
  {
    id: 101,
    patientId: 3,
    doctorId: 1,
    title: "Первичный осмотр",
    content: "Диагноз: ОРВИ. Назначено: парацетамол, постельный режим.",
    confidential: true,
    createdAt: "2026-05-12T10:00:00Z",
  },
  {
    id: 102,
    patientId: 3,
    doctorId: 2,
    title: "Повторный визит",
    content: "Анализы в норме. Продолжить лечение ещё 3 дня.",
    confidential: true,
    createdAt: "2026-05-20T14:30:00Z",
  },
  {
    id: 103,
    patientId: 4,
    doctorId: 1,
    title: "Кардиологическое обследование",
    content: "ЭКГ: синусовый ритм. Рекомендации по нагрузке. Следующий визит через месяц.",
    confidential: true,
    createdAt: "2026-05-18T09:15:00Z",
  },
  {
    id: 104,
    patientId: 4,
    doctorId: 2,
    title: "Конфиденциально — только для врача",
    content: "FLAG{BOLA_MEDICAL_RECORDS_LEAKED} — учебный флаг при утечке карты пациента Сидорова.",
    confidential: true,
    createdAt: "2026-06-01T11:00:00Z",
  },
];

const DEFAULT_APPOINTMENTS = [
  { id: 201, patientId: 3, doctorId: 1, date: "2026-06-10", reason: "Контрольный осмотр", room: "Каб. 12" },
  { id: 202, patientId: 4, doctorId: 2, date: "2026-06-12", reason: "Консультация по результатам", room: "Каб. 7" },
];

const DEFAULT_PRESCRIPTIONS = [
  {
    id: 301,
    patientId: 3,
    doctorId: 1,
    medication: "Парацетамол 500 мг",
    dosage: "2 раза в день после еды",
    issuedAt: "2026-05-12",
  },
  {
    id: 302,
    patientId: 4,
    doctorId: 1,
    medication: "Аторвастатин 20 мг",
    dosage: "1 таблетка вечером",
    issuedAt: "2026-05-18",
  },
];

let notes = DEFAULT_NOTES.map((n) => ({ ...n }));
let appointments = DEFAULT_APPOINTMENTS.map((a) => ({ ...a }));
let prescriptions = DEFAULT_PRESCRIPTIONS.map((p) => ({ ...p }));
let nextNoteId = 105;
const sessions = new Map();

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const parts = raw.split(";").map((s) => s.trim());
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq) === name) return decodeURIComponent(part.slice(eq + 1));
  }
  return null;
}

function setBolaAuth(res) {
  res.setHeader("Set-Cookie", `${BOLA_COOKIE}=1; Path=/bola; HttpOnly; SameSite=Lax`);
}

function clearBolaAuth(res) {
  res.setHeader("Set-Cookie", `${BOLA_COOKIE}=; Path=/bola; Max-Age=0; HttpOnly`);
}

function isBolaAuthed(req) {
  return getCookie(req, BOLA_COOKIE) === "1";
}

function gateBola(req, res, next) {
  if (OPEN_ACCESS || isBolaAuthed(req)) return next();
  res.redirect("/bola/login");
}

function resetBolaData() {
  notes = DEFAULT_NOTES.map((n) => ({ ...n }));
  appointments = DEFAULT_APPOINTMENTS.map((a) => ({ ...a }));
  prescriptions = DEFAULT_PRESCRIPTIONS.map((p) => ({ ...p }));
  nextNoteId = 105;
}

function createSession(user) {
  const accessToken = `mn_${user.id}_${crypto.randomBytes(12).toString("hex")}`;
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

function authMiddleware(req, res, next) {
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

function notesForUser(user) {
  if (user.role === "admin") return [...notes];
  if (user.role === "doctor") return notes.filter((n) => n.doctorId === user.id);
  if (user.role === "patient") return notes.filter((n) => n.patientId === user.id);
  return [];
}

function renderBolaLogin(escapeHtml, err) {
  const errHtml = err ? '<p class="practice-login__err">Неверный пароль</p>' : "";
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BOLA Lab — вход</title>
  <link rel="stylesheet" href="/style.css">
  <link rel="stylesheet" href="/bola.css">
</head>
<body>
  <header class="site-header">
    <p class="site-header__brand"><a href="/">BOLA Lab</a></p>
    <h1>MediNotes API</h1>
    <p class="subtitle">Доступ по паролю</p>
  </header>
  <main>
    <section class="practice-login">
      <p>BOLA Lab 1 — MediNotes. Пароль выдаёт преподаватель. <a href="/bola2/login">PayFlow (BOLA 2) →</a> · <a href="/bola3/login">CloudVault (BOLA 3) →</a></p>
      ${errHtml}
      <form method="POST" action="/bola/login">
        <label>Пароль <input type="password" name="password" autocomplete="current-password" required></label>
        <button type="submit">Войти</button>
      </form>
    </section>
  </main>
</body>
</html>`;
}

function renderBolaHome(escapeHtml) {
  const rows = USERS.map(
    (u) =>
      `<tr><td><code>${escapeHtml(u.username)}</code></td><td>${escapeHtml(u.role)}</td><td>${u.id}</td></tr>`
  ).join("");

  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BOLA Lab — MediNotes API</title>
  <link rel="stylesheet" href="/style.css">
  <link rel="stylesheet" href="/bola.css">
</head>
<body>
  <header class="site-header">
    <p class="site-header__brand"><a href="/">BOLA Lab</a></p>
    <h1>MediNotes API</h1>
    <p class="subtitle">Broken Object Level Authorization — учебный REST API</p>
    <nav class="nav" aria-label="Меню">
      <a href="/" class="nav__link">Главная</a>
      <a href="/bola" class="nav__link nav__link--active">BOLA 1</a>
      <a href="/bola2" class="nav__link">BOLA 2 (PayFlow)</a>
      <a href="/bola3" class="nav__link">BOLA 3 (CloudVault)</a>
      <a href="/bola/docs" class="nav__link">Swagger</a>
      <a href="/bola/openapi.yaml" class="nav__link">OpenAPI YAML</a>
    </nav>
  </header>

  <main>
    <section class="bola-card">
      <span class="badge badge--danger">Режим: уязвимый API</span>
      <h2>О лаборатории</h2>
      <p>API клиники <strong>MediNotes</strong>: медицинские записи, приёмы, рецепты. Аутентификация есть, но <strong>авторизация на уровне объектов отсутствует</strong> — классический BOLA (IDOR).</p>
      <p>Базовый URL: <code>http://localhost:3847/bola/api/v1</code></p>
    </section>

    <section class="bola-card">
      <h2>Тестовые пользователи</h2>
      <p>Это <strong>логины для POST /auth/login</strong>, не Bearer-токены. Пароль у всех один: пароль лаборатории. В ответе login придёт <code>accessToken</code> — его и ставьте в Authorize.</p>
      <table class="bola-table">
        <thead><tr><th>Логин</th><th>Роль</th><th>id</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>

    <section class="bola-card">
      <h2>Postman / curl — один логин → один токен</h2>
      <pre class="bola-pre">curl -s -X POST http://localhost:3847/bola/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"patient.kozlov","password":"portfolio-demo-only"}'</pre>
      <p>В ответе <code>accessToken</code> — подставьте в <code>Authorization: Bearer ...</code></p>
      <pre class="bola-pre">curl -s http://localhost:3847/bola/api/v1/notes/104 \\
  -H "Authorization: Bearer &lt;accessToken&gt;"</pre>
    </section>

    <section class="bola-card">
      <h2>Карта уязвимостей</h2>
      <ul class="bola-list">
        <li><code>GET /notes/{id}</code> — чтение любой записи по id</li>
        <li><code>GET /patients</code> — список всех пациентов</li>
        <li><code>GET /patients/{id}/notes</code> — все записи любого пациента</li>
        <li><code>GET /patients/{id}/export</code> — полное досье</li>
        <li><code>PUT /notes/{id}</code> — изменение чужой записи</li>
        <li><code>DELETE /notes/{id}</code> — удаление чужой записи</li>
        <li><code>POST /notes</code> — указание чужого <code>patientId</code></li>
        <li><code>GET /appointments/{id}</code>, <code>GET /prescriptions/{id}</code> — IDOR</li>
      </ul>
      <p>Подробности: <a href="/bola/docs">Swagger UI</a> · <a href="/bola/guide">Методичка</a></p>
    </section>

    <section class="bola-card">
      <h2>Сброс данных</h2>
      <form method="POST" action="/bola/reset" onsubmit="return confirm('Вернуть записи к исходному состоянию?')">
        <button type="submit" class="btn btn--danger">Сбросить API к дефолту</button>
      </form>
      <form class="practice-logout" method="POST" action="/bola/logout" style="margin-top:0.75rem">
        <button type="submit" class="btn btn--danger">Выйти из лаборатории</button>
      </form>
    </section>
  </main>

  <footer><p>Учебный пример. Только localhost.</p></footer>
</body>
</html>`;
}

function renderSwaggerPage() {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MediNotes API — Swagger</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css">
  <link rel="stylesheet" href="/bola.css">
</head>
<body class="bola-swagger-body">
  <header class="bola-swagger-bar">
    <a href="/bola">← BOLA Lab</a>
    <span>MediNotes API — Swagger UI</span>
    <a href="/bola/openapi.yaml">openapi.yaml</a>
  </header>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function () {
      SwaggerUIBundle({
        url: "/bola/openapi.yaml",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout",
        tryItOutEnabled: true,
        persistAuthorization: true,
        requestInterceptor: function (req) {
          if (!req.headers.Authorization && window.__bolaToken) {
            req.headers.Authorization = "Bearer " + window.__bolaToken;
          }
          return req;
        },
      });
    };
  </script>
</body>
</html>`;
}

function mountBola(app, { escapeHtml }) {
  const publicApi = express.Router();
  publicApi.use(express.json());

  publicApi.post("/auth/login", (req, res) => {
    const username = String(req.body.username || "").trim();
    const password = req.body.password || "";
    if (password !== BOLA_PASSWORD) {
      return res.status(401).json({
        error: "Invalid credentials",
        hint: "password — пароль лаборатории от преподавателя",
      });
    }
    const user = USERS.find((u) => u.username === username);
    if (!user) {
      return res.status(401).json({
        error: "Invalid credentials",
        hint: "username: patient.kozlov, patient.sidorov, dr.ivanov, dr.petrova, admin",
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

  api.use(authMiddleware);

  api.get("/", (req, res) => {
    res.json({
      name: "MediNotes API",
      version: "v1",
      user: publicUser(req.user),
      docs: "/bola/docs",
      login: "POST /auth/login",
      openapi: "/bola/openapi.yaml",
      endpoints: {
        "GET /users/me": "Профиль текущего пользователя",
        "GET /notes": "Список своих записей",
        "GET /notes/{id}": "Запись по id (BOLA — любая)",
        "POST /notes": "Создать запись",
        "PUT /notes/{id}": "Обновить запись (BOLA)",
        "DELETE /notes/{id}": "Удалить запись (BOLA)",
        "GET /patients": "Список всех пациентов (BOLA)",
        "GET /patients/{id}/notes": "Записи пациента (BOLA)",
        "GET /patients/{id}/export": "Экспорт досье (BOLA)",
        "GET /appointments/{id}": "Приём по id (BOLA)",
        "GET /prescriptions/{id}": "Рецепт по id (BOLA)",
      },
    });
  });

  api.get("/users/me", (req, res) => {
    res.json(publicUser(req.user));
  });

  api.get("/patients", (req, res) => {
    const list = USERS.filter((u) => u.role === "patient").map(publicUser);
    res.json({ patients: list, count: list.length });
  });

  api.get("/notes", (req, res) => {
    const list = notesForUser(req.user);
    res.json({ notes: list, count: list.length });
  });

  api.get("/notes/:noteId", (req, res) => {
    const note = notes.find((n) => n.id === Number(req.params.noteId));
    if (!note) return res.status(404).json({ error: "Note not found" });
    res.json(note);
  });

  api.post("/notes", (req, res) => {
    const { title, content, confidential } = req.body || {};
    if (!title || !content) {
      return res.status(400).json({ error: "title and content are required" });
    }
    let patientId = Number(req.body.patientId);
    if (!patientId) {
      if (req.user.role === "patient") patientId = req.user.id;
      else return res.status(400).json({ error: "patientId is required for doctors" });
    }
    const doctorId = req.user.role === "doctor" ? req.user.id : req.body.doctorId || 1;
    const note = {
      id: nextNoteId++,
      patientId,
      doctorId,
      title: String(title).slice(0, 200),
      content: String(content).slice(0, 2000),
      confidential: confidential !== false,
      createdAt: new Date().toISOString(),
    };
    notes.push(note);
    res.status(201).json(note);
  });

  api.put("/notes/:noteId", (req, res) => {
    const note = notes.find((n) => n.id === Number(req.params.noteId));
    if (!note) return res.status(404).json({ error: "Note not found" });
    if (req.body.title !== undefined) note.title = String(req.body.title).slice(0, 200);
    if (req.body.content !== undefined) note.content = String(req.body.content).slice(0, 2000);
    if (req.body.confidential !== undefined) note.confidential = Boolean(req.body.confidential);
    res.json(note);
  });

  api.delete("/notes/:noteId", (req, res) => {
    const id = Number(req.params.noteId);
    const idx = notes.findIndex((n) => n.id === id);
    if (idx === -1) return res.status(404).json({ error: "Note not found" });
    notes.splice(idx, 1);
    res.json({ deleted: true, id });
  });

  api.get("/patients/:patientId/notes", (req, res) => {
    const patientId = Number(req.params.patientId);
    const list = notes.filter((n) => n.patientId === patientId);
    res.json({ patientId, notes: list, count: list.length });
  });

  api.get("/patients/:patientId/export", (req, res) => {
    const patientId = Number(req.params.patientId);
    const patient = USERS.find((u) => u.id === patientId && u.role === "patient");
    if (!patient) return res.status(404).json({ error: "Patient not found" });
    res.json({
      patient: publicUser(patient),
      notes: notes.filter((n) => n.patientId === patientId),
      appointments: appointments.filter((a) => a.patientId === patientId),
      prescriptions: prescriptions.filter((p) => p.patientId === patientId),
    });
  });

  api.get("/appointments/:appointmentId", (req, res) => {
    const appt = appointments.find((a) => a.id === Number(req.params.appointmentId));
    if (!appt) return res.status(404).json({ error: "Appointment not found" });
    res.json(appt);
  });

  api.get("/prescriptions/:prescriptionId", (req, res) => {
    const rx = prescriptions.find((p) => p.id === Number(req.params.prescriptionId));
    if (!rx) return res.status(404).json({ error: "Prescription not found" });
    res.json(rx);
  });

  app.get("/bola/login", (req, res) => {
    if (OPEN_ACCESS || isBolaAuthed(req)) return res.redirect("/bola");
    const err = Boolean(req.query.err);
    res.send(renderBolaLogin(escapeHtml, err));
  });

  app.post("/bola/login", express.json(), (req, res) => {
    const password = req.body.password || "";
    if (password === BOLA_PASSWORD) {
      setBolaAuth(res);
      if (req.is("json")) {
        return res.json({
          ok: true,
          message: "Вход выполнен. Cookie bolaauth установлен — используйте его в следующих запросах.",
        });
      }
      return res.redirect("/bola");
    }
    if (req.is("json")) {
      return res.status(401).json({ error: "Invalid password", hint: "password: portfolio-demo-only" });
    }
    res.redirect("/bola/login?err=1");
  });

  app.post("/bola/logout", (req, res) => {
    clearBolaAuth(res);
    res.redirect("/bola/login");
  });

  app.get("/bola", gateBola, (req, res) => {
    res.send(renderBolaHome(escapeHtml));
  });

  app.get("/bola/docs", gateBola, (req, res) => {
    res.send(renderSwaggerPage());
  });

  app.get("/bola/openapi.yaml", gateBola, (req, res) => {
    const yamlPath = path.join(__dirname, "DOCS", "bola-openapi.yaml");
    res.type("text/yaml").send(fs.readFileSync(yamlPath, "utf8"));
  });

  app.get("/bola/guide", gateBola, (req, res) => {
    const md = fs.readFileSync(path.join(__dirname, "DOCS", "bola1.txt"), "utf8");
    const body = md
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
    res.send(`<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>BOLA — методичка</title>
      <link rel="stylesheet" href="/style.css"><link rel="stylesheet" href="/bola.css"></head>
      <body><p class="site-header__brand"><a href="/bola">← BOLA Lab</a></p>
      <pre class="bola-pre" style="white-space:pre-wrap">${body}</pre></body></html>`);
  });

  app.post("/bola/reset", gateBola, (req, res) => {
    resetBolaData();
    res.redirect("/bola");
  });

  app.use("/bola/api/v1", publicApi);
  app.use("/bola/api/v1", api);
}

module.exports = { mountBola, resetBolaData, USERS, BOLA_PASSWORD };
