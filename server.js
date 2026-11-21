/**
 * Учебный сервер: BOLA / IDOR (намеренно уязвимый).
 * Запускайте только локально.
 */

const express = require("express");
const path = require("path");
const { OPEN_ACCESS } = require("./lab-config");
const { mountBola } = require("./bola-lab");
const { mountBola2 } = require("./bola2-lab");
const { mountBola3 } = require("./bola3-lab");

const app = express();
const PORT = Number(process.env.PORT) || 3847;

const BOLA_CATALOG = [
  {
    href: "/bola",
    label: "BOLA 1 — MediNotes",
    desc: "Медицинский портал, IDOR",
  },
  {
    href: "/bola2",
    label: "BOLA 2 — PayFlow",
    desc: "Финтех, 12 заданий",
  },
  {
    href: "/bola3",
    label: "BOLA 3 — CloudVault",
    desc: "Multi-tenant, UUID, 15 заданий",
  },
];

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderLabCard(item) {
  return `<article class="other-card">
    <h3 class="other-card__title"><a href="${item.href}">${escapeHtml(item.label)}</a></h3>
    <p class="other-card__desc">${escapeHtml(item.desc)}</p>
    <a href="${item.href}" class="other-card__link">Открыть →</a>
  </article>`;
}

function renderHome() {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BOLA Lab</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body class="page-home">
  <header class="site-header">
    <p class="site-header__brand"><a href="/">BOLA Lab</a></p>
    <h1>BOLA Lab</h1>
    <p class="subtitle">Broken Object Level Authorization · пароль у преподавателя</p>
  </header>

  <div class="other-page">
    <section class="other-group">
      <div class="other-group__head">
        <h2 class="other-group__title">Лаборатории</h2>
        <p class="other-group__note">Аутентификация есть, проверки доступа к объекту — нет</p>
      </div>
      <div class="other-grid">${BOLA_CATALOG.map(renderLabCard).join("")}</div>
    </section>
  </div>

  <footer>
    <p>Учебный пример. Только localhost.</p>
  </footer>
</body>
</html>`;
}

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (_req, res) => {
  res.send(renderHome());
});

app.get("/other", (_req, res) => {
  res.redirect("/");
});

mountBola(app, { escapeHtml });
mountBola2(app, { escapeHtml });
mountBola3(app, { escapeHtml });

app.listen(PORT, "127.0.0.1", () => {
  const accessNote = OPEN_ACCESS ? "без пароля" : "пароли у преподавателя";
  console.log(`\n  BOLA Lab: http://localhost:${PORT}/`);
  console.log(`  BOLA 1:   /bola   — MediNotes   (${accessNote})`);
  console.log(`  BOLA 2:   /bola2  — PayFlow     (${accessNote})`);
  console.log(`  BOLA 3:   /bola3  — CloudVault  (${accessNote})\n`);
});
