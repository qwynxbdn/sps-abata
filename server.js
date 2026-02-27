// ==========================================
// File: server.js (Final Fix - Local & Vercel)
// ==========================================
require("dotenv").config();
const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// --- KONEKSI DATABASE ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ ok: false, error: "Silakan login" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ ok: false, error: "Sesi berakhir" });
    req.user = user;
    next();
  });
};

// ==========================================
// API ROUTES (Taruh di atas rute statis)
// ==========================================

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const userRes = await pool.query("SELECT * FROM Users WHERE Username = $1 AND IsActive = TRUE", [username]);
    if (userRes.rows.length === 0) return res.status(401).json({ ok: false, error: "User tidak ditemukan" });

    const user = userRes.rows[0];
    const valid = await bcrypt.compare(password, user.passwordhash);
    if (!valid) return res.status(401).json({ ok: false, error: "Password salah" });

    const roleRes = await pool.query("SELECT PermissionsJson FROM Roles WHERE Role = $1", [user.role]);
    const permissions = roleRes.rows[0].permissionsjson;

    const token = jwt.sign({ userId: user.userid, username: user.username, role: user.role, permissions }, process.env.JWT_SECRET, { expiresIn: "12h" });
    res.json({ ok: true, data: { token, user: { UserId: user.userid, Name: user.name, Role: user.role, permissions } } });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.get("/api/reports/monthly", authenticateToken, async (req, res) => {
  const { month, year } = req.query;
  try {
    const result = await pool.query(`
      WITH RECURSIVE hours AS (SELECT 0 AS start_hour UNION ALL SELECT start_hour + 2 FROM hours WHERE start_hour < 22),
      days AS (SELECT generate_series(date_trunc('month', make_date($2, $1, 1)), (date_trunc('month', make_date($2, $1, 1)) + interval '1 month' - interval '1 day'), interval '1 day')::date AS date)
      SELECT TO_CHAR(d.date, 'DD/MM/YYYY') as tanggal, h.start_hour || ':00 - ' || (h.start_hour + 2) || ':00' AS window, c.Name AS lokasi, COALESCE(l.Username, '-') AS petugas, CASE WHEN l.LogId IS NULL THEN 'ABSENT' ELSE 'OK' END AS status
      FROM days d CROSS JOIN hours h CROSS JOIN Checkpoints c
      LEFT JOIN PatrolLogs l ON l.CheckpointId = c.CheckpointId AND l.Timestamp::date = d.date AND EXTRACT(HOUR FROM l.Timestamp) >= h.start_hour AND EXTRACT(HOUR FROM l.Timestamp) < (h.start_hour + 2)
      ORDER BY d.date ASC, h.start_hour ASC, c.Name ASC;
    `, [parseInt(month), parseInt(year)]);
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ==========================================
// STATIC FILES & VERCEL ROUTING FIX
// ==========================================

// 1. Sajikan folder public
app.use(express.static(path.join(__dirname, "public")));

// 2. Perbaikan rute untuk "/"
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// 3. FIX ERROR PathToRegexp: Gunakan rute wildcard dengan parameter nama
app.get("/:any*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ==========================================
// EKSEKUSI
// ==========================================

// Export untuk Vercel
module.exports = app;

// Jalankan server jika di local
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Server menyala di http://localhost:${PORT}`);
  });
}