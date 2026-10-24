require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const Stripe = require("stripe");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET in .env to a random string of at least 32 characters.");
  process.exit(1);
}

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "vista.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    preview_url TEXT NOT NULL,
    full_url TEXT,
    price_cents INTEGER NOT NULL DEFAULT 199,
    creator_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (creator_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS likes (
    user_id INTEGER NOT NULL,
    video_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, video_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (video_id) REFERENCES videos(id)
  );
  CREATE TABLE IF NOT EXISTS subscriptions (
    user_id INTEGER NOT NULL,
    creator_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, creator_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (creator_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    video_id INTEGER NOT NULL,
    provider_session_id TEXT UNIQUE,
    paid_at TEXT,
    UNIQUE(user_id, video_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (video_id) REFERENCES videos(id)
  );
`);

const sampleCount = db.prepare("SELECT COUNT(*) AS n FROM videos").get().n;
if (sampleCount === 0) {
  const insert = db.prepare("INSERT INTO videos (title, description, preview_url, full_url, price_cents) VALUES (?, ?, ?, ?, ?)");
  insert.run(
    "Пример видео VISTA",
    "Демонстрационная запись. Замените URL на свои подготовленные preview и full video потоки.",
    "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
    "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
    199
  );
}

// Stripe webhook needs the raw body, so register it before express.json().
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.post("/api/payments/webhook", express.raw({ type: "application/json" }), (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(503).send("Payments are not configured.");
  }
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Invalid webhook signature: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    if (session.payment_status === "paid" && session.metadata?.userId && session.metadata?.videoId) {
      db.prepare(`
        INSERT INTO purchases (user_id, video_id, provider_session_id, paid_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, video_id) DO UPDATE SET
          provider_session_id=excluded.provider_session_id,
          paid_at=excluded.paid_at
      `).run(Number(session.metadata.userId), Number(session.metadata.videoId), session.id);
    }
  }
  res.json({ received: true });
});

app.use(helmet({
  // For a production video player, configure a strict CSP and media host allowlist.
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());
app.use("/api", rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, "public")));

function makeToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}
function setAuthCookie(res, token) {
  res.cookie("vista_session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/"
  });
}
function optionalAuth(req, res, next) {
  const token = req.cookies?.vista_session;
  if (!token) return next();
  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch (_) {
    res.clearCookie("vista_session", { path: "/" });
  }
  next();
}
function requireAuth(req, res, next) {
  optionalAuth(req, res, () => {
    if (!req.user) return res.status(401).json({ error: "Войдите в аккаунт, чтобы продолжить." });
    next();
  });
}

app.post("/api/auth/register", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Введите корректный email." });
  if (password.length < 10) return res.status(400).json({ error: "Пароль должен содержать не менее 10 символов." });
  if (password.length > 72) return res.status(400).json({ error: "Пароль слишком длинный." });

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)").run(email, hash);
    const user = { id: Number(result.lastInsertRowid), email };
    setAuthCookie(res, makeToken(user));
    res.status(201).json({ user });
  } catch (err) {
    if (String(err.code).includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "Этот email уже зарегистрирован." });
    res.status(500).json({ error: "Не удалось создать аккаунт." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const row = db.prepare("SELECT id, email, password_hash FROM users WHERE email = ?").get(email);
  if (!row || !(await bcrypt.compare(password, row.password_hash))) {
    return res.status(401).json({ error: "Неверный email или пароль." });
  }
  setAuthCookie(res, makeToken({ id: row.id, email: row.email }));
  res.json({ user: { id: row.id, email: row.email } });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("vista_session", { path: "/" });
  res.json({ ok: true });
});

app.get("/api/me", optionalAuth, (req, res) => {
  res.json({ user: req.user ? { id: Number(req.user.sub), email: req.user.email } : null });
});

app.get("/api/videos", optionalAuth, (req, res) => {
  const videos = db.prepare(`
    SELECT v.id, v.title, v.description, v.preview_url, v.price_cents,
      (SELECT COUNT(*) FROM likes l WHERE l.video_id=v.id) AS likes,
      CASE WHEN ? IS NOT NULL AND EXISTS (
        SELECT 1 FROM purchases p WHERE p.user_id=? AND p.video_id=v.id AND p.paid_at IS NOT NULL
      ) THEN 1 ELSE 0 END AS purchased
    FROM videos v ORDER BY v.id DESC
  `).all(req.user ? Number(req.user.sub) : null, req.user ? Number(req.user.sub) : null);
  res.json({ videos });
});

// This route deliberately returns ONLY preview_url. Full URLs are never exposed by the list API.
app.get("/api/videos/:id/preview", (req, res) => {
  const video = db.prepare("SELECT id, preview_url FROM videos WHERE id=?").get(Number(req.params.id));
  if (!video) return res.status(404).json({ error: "Видео не найдено." });
  res.json({ videoId: video.id, previewUrl: video.preview_url, previewSeconds: 20 });
});

app.get("/api/videos/:id/full", requireAuth, (req, res) => {
  const video = db.prepare("SELECT id, full_url FROM videos WHERE id=?").get(Number(req.params.id));
  if (!video) return res.status(404).json({ error: "Видео не найдено." });
  const paid = db.prepare("SELECT 1 FROM purchases WHERE user_id=? AND video_id=? AND paid_at IS NOT NULL")
    .get(Number(req.user.sub), video.id);
  if (!paid) return res.status(402).json({ error: "Для полной версии сначала оплатите доступ.", paymentRequired: true });
  if (!video.full_url) return res.status(404).json({ error: "Полная версия пока не загружена." });
  res.json({ videoId: video.id, fullUrl: video.full_url });
});

app.post("/api/videos/:id/like", requireAuth, (req, res) => {
  const videoId = Number(req.params.id);
  if (!db.prepare("SELECT 1 FROM videos WHERE id=?").get(videoId)) return res.status(404).json({ error: "Видео не найдено." });
  const existing = db.prepare("SELECT 1 FROM likes WHERE user_id=? AND video_id=?").get(Number(req.user.sub), videoId);
  if (existing) db.prepare("DELETE FROM likes WHERE user_id=? AND video_id=?").run(Number(req.user.sub), videoId);
  else db.prepare("INSERT INTO likes (user_id, video_id) VALUES (?, ?)").run(Number(req.user.sub), videoId);
  const likes = db.prepare("SELECT COUNT(*) AS n FROM likes WHERE video_id=?").get(videoId).n;
  res.json({ liked: !existing, likes });
});

app.post("/api/creators/:id/subscribe", requireAuth, (req, res) => {
  const creatorId = Number(req.params.id);
  if (!db.prepare("SELECT 1 FROM users WHERE id=?").get(creatorId)) return res.status(404).json({ error: "Автор не найден." });
  if (creatorId === Number(req.user.sub)) return res.status(400).json({ error: "Нельзя подписаться на самого себя." });
  const existing = db.prepare("SELECT 1 FROM subscriptions WHERE user_id=? AND creator_id=?").get(Number(req.user.sub), creatorId);
  if (existing) db.prepare("DELETE FROM subscriptions WHERE user_id=? AND creator_id=?").run(Number(req.user.sub), creatorId);
  else db.prepare("INSERT INTO subscriptions (user_id, creator_id) VALUES (?, ?)").run(Number(req.user.sub), creatorId);
  res.json({ subscribed: !existing });
});

app.post("/api/videos/:id/checkout", requireAuth, async (req, res) => {
  const video = db.prepare("SELECT id, title, price_cents FROM videos WHERE id=?").get(Number(req.params.id));
  if (!video) return res.status(404).json({ error: "Видео не найдено." });
  const paid = db.prepare("SELECT 1 FROM purchases WHERE user_id=? AND video_id=? AND paid_at IS NOT NULL").get(Number(req.user.sub), video.id);
  if (paid) return res.status(409).json({ error: "Доступ уже оплачен." });
  if (!stripe) return res.status(503).json({
    error: "Платежи ещё не настроены. Нужен аккаунт платёжного провайдера, который поддерживает вашу страну и бизнес."
  });

  try {
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      customer_email: req.user.email,
      line_items: [{
        price_data: {
          currency: "usd",
          product_data: { name: `TeamSh — ${video.title}` },
          unit_amount: video.price_cents
        },
        quantity: 1
      }],
      metadata: { userId: String(req.user.sub), videoId: String(video.id) },
      success_url: `${BASE_URL}/?payment=success`,
      cancel_url: `${BASE_URL}/?payment=cancelled`
    });
    res.json({ checkoutUrl: session.url });
  } catch (err) {
    console.error("Checkout creation failed:", err.message);
    res.status(502).json({ error: "Платёжная сессия не создана. Проверьте настройки провайдера." });
  }
});

// Demo upload metadata endpoint. It intentionally does not accept/store raw video files.
// Production uploads need object storage, size/type checks, malware scanning and paid upload checkout.
app.post("/api/uploads/quote", requireAuth, (req, res) => {
  const sizeMb = Number(req.body?.sizeMb);
  if (!Number.isFinite(sizeMb) || sizeMb <= 0 || sizeMb > 2048) {
    return res.status(400).json({ error: "Укажите размер видео от 0 до 2048 МБ." });
  }
  const priceCents = Math.max(99, Math.ceil(sizeMb * 2));
  res.json({
    sizeMb,
    priceCents,
    currency: "USD",
    message: "Это предварительный расчёт. Реальная платная загрузка включается после подключения хранилища и платёжного процесса."
  });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => {
  console.log(`TeamSh is running at ${BASE_URL}`);
});
