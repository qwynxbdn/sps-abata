// ==========================================
// File: server.js (VERSI KOMPATIBEL DATABASE LAMA)
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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// --- HELPER: FUNGSI HITUNG JARAK ---
function getDistance(lat1, lon1, lat2, lon2) {
  const R = 6371000; // Radius bumi dalam meter
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c; // Hasil dalam meter
}

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

// --- AUTH & ME ---
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

// --- GET ALL SCHEDULES ---
app.get("/api/schedules", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        s.ScheduleId as "ScheduleId", 
        s.UserId as "UserId",
        s.CheckpointId as "CheckpointId",
        u.Name as "Petugas", 
        c.Name as "Lokasi", 
        s.ShiftName as "Shift", 
        TO_CHAR(s.ScheduleDate, 'YYYY-MM-DD') as "TanggalRaw",
        TO_CHAR(s.ScheduleDate, 'DD/MM/YYYY') as "Tanggal"
      FROM Schedules s
      JOIN Users u ON s.UserId = u.UserId
      JOIN Checkpoints c ON s.CheckpointId = c.CheckpointId
      ORDER BY s.ScheduleDate DESC
    `);
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// --- CREATE SCHEDULE ---
app.post("/api/schedules", authenticateToken, async (req, res) => {
  const { UserId, CheckpointId, ShiftName, ScheduleDate, StartTime, EndTime } = req.body;
  try {
    await pool.query(
      "INSERT INTO Schedules (UserId, CheckpointId, ShiftName, ScheduleDate, StartTime, EndTime) VALUES ($1, $2, $3, $4, $5, $6)",
      [UserId, CheckpointId, ShiftName, ScheduleDate, StartTime, EndTime]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// --- UPDATE SCHEDULE ---
app.put("/api/schedules", authenticateToken, async (req, res) => {
  const { ScheduleId, UserId, CheckpointId, ShiftName, ScheduleDate, StartTime, EndTime } = req.body;
  try {
    await pool.query(
      "UPDATE Schedules SET UserId=$1, CheckpointId=$2, ShiftName=$3, ScheduleDate=$4, StartTime=$5, EndTime=$6 WHERE ScheduleId=$7",
      [UserId, CheckpointId, ShiftName, ScheduleDate, StartTime, EndTime, ScheduleId]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.get("/api/reports/matrix", authenticateToken, async (req, res) => {
  const { month, year } = req.query;
  try {
    const query = `
      WITH RECURSIVE hours AS (
          SELECT 7 AS start_hour, 1 AS step
          UNION ALL 
          SELECT (start_hour + 2) % 24, step + 1 FROM hours WHERE step < 12
      ),
      days AS (
          SELECT generate_series(
            date_trunc('month', make_date($2, $1, 1)), 
            (date_trunc('month', make_date($2, $1, 1)) + interval '1 month' - interval '1 day'), 
            interval '1 day'
          )::date AS date
      )
      SELECT 
        EXTRACT(DAY FROM d.date) as tgl, 
        LPAD(h.start_hour::text, 2, '0') || ':00' AS jam_slot, 
        c.Name AS lokasi, 
        UPPER(LEFT(COALESCE(l.Username, ''), 3)) AS inisial
      FROM days d 
      CROSS JOIN hours h 
      CROSS JOIN Checkpoints c
      LEFT JOIN PatrolLogs l ON 
        l.CheckpointId = c.CheckpointId AND 
        l.Timestamp::date = d.date AND
        (
          -- Logika jam agar scan jam 08:30 masuk ke slot 07:00
          (h.start_hour <= 22 AND EXTRACT(HOUR FROM l.Timestamp) >= h.start_hour AND EXTRACT(HOUR FROM l.Timestamp) < h.start_hour + 2)
          OR
          (h.start_hour = 23 AND (EXTRACT(HOUR FROM l.Timestamp) >= 23 OR EXTRACT(HOUR FROM l.Timestamp) < 1))
          OR
          (h.start_hour < 7 AND EXTRACT(HOUR FROM l.Timestamp) >= h.start_hour AND EXTRACT(HOUR FROM l.Timestamp) < h.start_hour + 2)
        )
      ORDER BY h.step ASC, lokasi ASC, tgl ASC;
    `;
    const result = await pool.query(query, [parseInt(month), parseInt(year)]);
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// --- SCAN (VERSI TANPA KOLOM GPS) ---
app.post("/api/scan", authenticateToken, async (req, res) => {
  const { barcode, lat, lng } = req.body; // Data dari HP petugas
  try {
    // 1. Ambil data titik koordinat checkpoint dari database
    const cpRes = await pool.query("SELECT * FROM Checkpoints WHERE BarcodeValue = $1 AND Active = TRUE", [barcode]);
    if (cpRes.rows.length === 0) return res.status(404).json({ ok: false, error: "Checkpoint tidak ditemukan!" });

    const cp = cpRes.rows[0];
    
    // 2. LOGIKA VALIDASI JARAK (PENTING!)
    // Kita bandingkan lokasi HP (lat, lng) dengan lokasi Checkpoint (cp.latitude, cp.longitude)
    if (cp.latitude && cp.longitude) {
      const distance = getDistance(lat, lng, parseFloat(cp.latitude), parseFloat(cp.longitude));
      const radiusLimit = cp.radiusmeters || 50; // Default 50 meter jika tidak diisi

      if (distance > radiusLimit) {
        return res.status(400).json({ 
          ok: false, 
          error: `Anda terlalu jauh dari lokasi! Jarak: ${Math.round(distance)} meter.` 
        });
      }
    }

    // 3. SIMPAN LOG (SESUAIKAN DENGAN KOLOM DB ANDA)
    // Jangan masukkan Latitude/Longitude ke sini jika tabel PatrolLogs Anda tidak punya kolomnya!
    await pool.query(
      "INSERT INTO PatrolLogs (CheckpointId, UserId, Username, BarcodeValue, Timestamp, Result) VALUES ($1, $2, $3, $4, NOW(), $5)",
      [cp.checkpointid, req.user.userId, req.user.username, barcode, 'OK']
    );

    res.json({ ok: true, data: { locationName: cp.name } });
  } catch (err) { 
    res.status(500).json({ ok: false, error: err.message }); 
  }
});
// --- USERS CRUD ---
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
    await pool.query("INSERT INTO Users (Name, Username, PasswordHash, Role, IsActive) VALUES ($1, $2, $3, $4, $5)", [Name, Username, hash, Role, IsActive]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.put("/api/users", authenticateToken, async (req, res) => {
  const { UserId, Name, Password, Role, IsActive } = req.body;
  try {
    if (Password && Password.trim() !== "") {
      const hash = await bcrypt.hash(Password, 10);
      await pool.query("UPDATE Users SET Name=$1, PasswordHash=$2, Role=$3, IsActive=$4 WHERE UserId=$5", [Name, hash, Role, IsActive, UserId]);
    } else {
      await pool.query("UPDATE Users SET Name=$1, Role=$2, IsActive=$3 WHERE UserId=$4", [Name, Role, IsActive, UserId]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// --- CHECKPOINTS CRUD ---
app.get("/api/checkpoints", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT CheckpointId as \"CheckpointId\", Name as \"Name\", BarcodeValue as \"BarcodeValue\", Active as \"Active\" FROM Checkpoints ORDER BY Name ASC");
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.post("/api/checkpoints", authenticateToken, async (req, res) => {
  const { Name, BarcodeValue, Active } = req.body;
  try {
    await pool.query("INSERT INTO Checkpoints (Name, BarcodeValue, Active) VALUES ($1, $2, $3)", [Name, BarcodeValue, Active]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.put("/api/checkpoints", authenticateToken, async (req, res) => {
  const { CheckpointId, Name, BarcodeValue, Active } = req.body;
  try {
    await pool.query("UPDATE Checkpoints SET Name=$1, BarcodeValue=$2, Active=$3 WHERE CheckpointId=$4", [Name, BarcodeValue, Active, CheckpointId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// --- LOGS & REPORTS ---
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
      // Ganti bagian query hours di /api/reports/matrix menjadi:
WITH RECURSIVE hours AS (
    SELECT 7 AS start_hour, 1 AS step
    UNION ALL 
    SELECT (start_hour + 2) % 24, step + 1 FROM hours WHERE step < 12
),
      days AS (SELECT generate_series(date_trunc('month', make_date($2, $1, 1)), (date_trunc('month', make_date($2, $1, 1)) + interval '1 month' - interval '1 day'), interval '1 day')::date AS date)
      SELECT EXTRACT(DAY FROM d.date) as tgl, TO_CHAR(make_timestamp(2000, 1, 1, h.start_hour, 0, 0), 'HH24:00') AS jam_slot, c.Name AS lokasi, UPPER(LEFT(COALESCE(l.Username, ''), 3)) AS inisial
      FROM days d CROSS JOIN hours h CROSS JOIN Checkpoints c
      LEFT JOIN PatrolLogs l ON l.CheckpointId = c.CheckpointId AND l.Timestamp::date = d.date AND EXTRACT(HOUR FROM l.Timestamp) >= h.start_hour AND EXTRACT(HOUR FROM l.Timestamp) < (h.start_hour + 2)
      ORDER BY jam_slot ASC, lokasi ASC, tgl ASC;
    `;
    const result = await pool.query(query, [parseInt(month), parseInt(year)]);
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// --- ROUTING FIX ---
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get(/^\/(?!api).*/, (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

module.exports = app;




