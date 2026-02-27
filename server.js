// ==========================================
// File: server.js (Full Version: View & CRUD)
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

// --- DATABASE CONNECTION ---
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
// API ROUTES: AUTH & PROFILE
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

app.get("/api/me", authenticateToken, async (req, res) => {
  try {
    const userRes = await pool.query("SELECT UserId as \"UserId\", Name as \"Name\", Username as \"Username\", Role as \"Role\" FROM Users WHERE UserId = $1", [req.user.userId]);
    res.json({ ok: true, data: { ...userRes.rows[0], permissions: req.user.permissions } });
  } catch (err) { res.status(500).json({ ok: false }); }
});

// ==========================================
// API ROUTES: MANAJEMEN CHECKPOINT (VIEW & SAVE)
// ==========================================

app.get("/api/checkpoints", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT CheckpointId as \"CheckpointId\", Name as \"Name\", BarcodeValue as \"BarcodeValue\", Latitude as \"Latitude\", Longitude as \"Longitude\", RadiusMeters as \"RadiusMeters\", Active as \"Active\" FROM Checkpoints ORDER BY Name ASC");
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// Endpoint untuk TAMBAH Checkpoint Baru
app.post("/api/checkpoints", authenticateToken, async (req, res) => {
  const { Name, BarcodeValue, Latitude, Longitude, RadiusMeters, Active } = req.body;
  try {
    await pool.query(
      "INSERT INTO Checkpoints (Name, BarcodeValue, Latitude, Longitude, RadiusMeters, Active) VALUES ($1, $2, $3, $4, $5, $6)",
      [Name, BarcodeValue, Latitude, Longitude, RadiusMeters, Active]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// Endpoint untuk EDIT Checkpoint
app.put("/api/checkpoints", authenticateToken, async (req, res) => {
  const { CheckpointId, Name, BarcodeValue, Latitude, Longitude, RadiusMeters, Active } = req.body;
  try {
    await pool.query(
      "UPDATE Checkpoints SET Name=$1, BarcodeValue=$2, Latitude=$3, Longitude=$4, RadiusMeters=$5, Active=$6 WHERE CheckpointId=$7",
      [Name, BarcodeValue, Latitude, Longitude, RadiusMeters, Active, CheckpointId]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ==========================================
// API ROUTES: MANAJEMEN USERS (VIEW & SAVE)
// ==========================================

app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT UserId as \"UserId\", Name as \"Name\", Username as \"Username\", Role as \"Role\", IsActive as \"IsActive\" FROM Users ORDER BY Name ASC");
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.post("/api/users", authenticateToken, async (req, res) => {
  const { Name, Username, Password, Role, IsActive } = req.body;
  try {
    const hash = await bcrypt.hash(Password, 10);
    await pool.query(
      "INSERT INTO Users (Name, Username, PasswordHash, Role, IsActive) VALUES ($1, $2, $3, $4, $5)",
      [Name, Username, hash, Role, IsActive]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ==========================================
// API ROUTES: LOGS & REPORTS
// ==========================================

app.get("/api/patrollogs", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT LogId as \"LogId\", Timestamp as \"Timestamp\", Username as \"Username\", BarcodeValue as \"BarcodeValue\", Result as \"Result\" FROM PatrolLogs ORDER BY Timestamp DESC LIMIT 200");
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.get("/api/reports/matrix", authenticateToken, async (req, res) => {
  const { month, year } = req.query;
  try {
    const query = `
      WITH RECURSIVE hours AS (
        SELECT 7 AS start_hour UNION ALL SELECT start_hour + 2 FROM hours WHERE start_hour < 23
      ),
      days AS (
        SELECT generate_series(date_trunc('month', make_date($2, $1, 1)), (date_trunc('month', make_date($2, $1, 1)) + interval '1 month' - interval '1 day'), interval '1 day')::date AS date
      )
      SELECT EXTRACT(DAY FROM d.date) as tgl, TO_CHAR(make_timestamp(2000, 1, 1, h.start_hour, 0, 0), 'HH24:00') AS jam_slot, c.Name AS lokasi, UPPER(LEFT(COALESCE(l.Username, ''), 3)) AS inisial
      FROM days d CROSS JOIN hours h CROSS JOIN Checkpoints c
      LEFT JOIN PatrolLogs l ON l.CheckpointId = c.CheckpointId AND l.Timestamp::date = d.date AND EXTRACT(HOUR FROM l.Timestamp) >= h.start_hour AND EXTRACT(HOUR FROM l.Timestamp) < (h.start_hour + 2)
      ORDER BY jam_slot ASC, lokasi ASC, tgl ASC;
    `;
    const result = await pool.query(query, [parseInt(month), parseInt(year)]);
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ==========================================
// STATIC FILES & ROUTING FIX
// ==========================================
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get(/^\/(?!api).*/, (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

module.exports = app;
