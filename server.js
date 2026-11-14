const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const db = new Database("lucky-travelling.db");
const PORT = process.env.PORT || 3000;

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'customer'
);
CREATE TABLE IF NOT EXISTS bookings (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 customer_name TEXT NOT NULL,
 phone TEXT NOT NULL,
 service TEXT NOT NULL,
 vehicle TEXT NOT NULL,
 pickup TEXT NOT NULL,
 destination TEXT NOT NULL,
 travel_date TEXT NOT NULL,
 passengers INTEGER DEFAULT 1,
 notes TEXT,
 status TEXT NOT NULL DEFAULT 'Pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const adminUser = process.env.ADMIN_USERNAME || "admin";
const adminPass = process.env.ADMIN_PASSWORD || "ChangeThisPassword123!";
const exists = db.prepare("SELECT id FROM users WHERE email=?").get("admin@lucky.local");
if (!exists) {
  db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)")
    .run("Administrator", "admin@lucky.local", bcrypt.hashSync(adminPass, 10), "admin");
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-session-secret",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, "public")));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please log in first." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ error: "Admin access required." });
  next();
}

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(String(email || "").trim().toLowerCase());
  if (!user || !bcrypt.compareSync(String(password || ""), user.password_hash))
    return res.status(401).json({ error: "Invalid email or password." });
  req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
  res.json({ user: req.session.user });
});

app.post("/api/register", (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || String(password).length < 8)
    return res.status(400).json({ error: "Enter name, email and a password of at least 8 characters." });
  try {
    const hash = bcrypt.hashSync(String(password), 10);
    const info = db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'customer')")
      .run(String(name).trim(), String(email).trim().toLowerCase(), hash);
    req.session.user = { id: info.lastInsertRowid, name, email, role: "customer" };
    res.json({ user: req.session.user });
  } catch {
    res.status(409).json({ error: "This email is already registered." });
  }
});

app.get("/api/me", (req, res) => res.json({ user: req.session.user || null }));
app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.post("/api/bookings", (req, res) => {
  const b = req.body;
  const required = ["customer_name", "phone", "service", "vehicle", "pickup", "destination", "travel_date"];
  if (required.some(k => !String(b[k] || "").trim()))
    return res.status(400).json({ error: "Please complete all required booking fields." });
  const result = db.prepare(`
    INSERT INTO bookings(customer_name,phone,service,vehicle,pickup,destination,travel_date,passengers,notes)
    VALUES(@customer_name,@phone,@service,@vehicle,@pickup,@destination,@travel_date,@passengers,@notes)
  `).run({
    customer_name: String(b.customer_name).trim(), phone: String(b.phone).trim(),
    service: String(b.service), vehicle: String(b.vehicle),
    pickup: String(b.pickup).trim(), destination: String(b.destination).trim(),
    travel_date: String(b.travel_date), passengers: Number(b.passengers || 1),
    notes: String(b.notes || "").trim()
  });
  res.status(201).json({ bookingId: result.lastInsertRowid, message: "Booking request saved. Payment is offline." });
});

app.get("/api/my-bookings", requireLogin, (req, res) => {
  // The current starter links bookings by phone number; customer enters the same phone at booking.
  const rows = db.prepare("SELECT * FROM bookings WHERE phone=? ORDER BY id DESC")
    .all(req.query.phone || "");
  res.json({ bookings: rows });
});

app.get("/api/admin/bookings", requireAdmin, (req, res) => {
  res.json({ bookings: db.prepare("SELECT * FROM bookings ORDER BY id DESC").all() });
});
app.patch("/api/admin/bookings/:id", requireAdmin, (req, res) => {
  const allowed = ["Pending", "Confirmed", "Rejected", "Completed"];
  if (!allowed.includes(req.body.status)) return res.status(400).json({ error: "Invalid status." });
  const result = db.prepare("UPDATE bookings SET status=? WHERE id=?").run(req.body.status, req.params.id);
  if (!result.changes) return res.status(404).json({ error: "Booking not found." });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Lucky Travelling Co. running at http://localhost:${PORT}`));
