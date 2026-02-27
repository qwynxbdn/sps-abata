require("dotenv").config();
const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

// --- KONFIGURASI MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// --- KONEKSI DATABASE ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ==========================================
// MIDDLEWARE KEAMANAN
// ==========================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ ok: false, error: "Silakan login terlebih dahulu" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ ok: false, error: "Sesi berakhir, silakan login ulang" });
    req.user = user;
    next();
  });
};

const requirePermission = (permission) => {
  return (req, res, next) => {
    const perms = req.user.permissions || [];
    if (perms.includes("all") || perms.includes(permission) || perms.includes(permission.split(".")[0] + ".*")) {
      next();
    } else {
      res.status(403).json({ ok: false, error: "Akses ditolak" });
    }
  };
};

// ==========================================
// API ENDPOINTS
// ==========================================

// 1. AUTHENTICATION
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const userRes = await pool.query("SELECT * FROM Users WHERE Username = $1 AND IsActive = TRUE", [username]);
    if (userRes.rows.length === 0) return res.status(401).json({ ok: false, error: "Username tidak ditemukan" });

    const user = userRes.rows[0];
    const valid = await bcrypt.compare(password, user.passwordhash);
    if (!valid) return res.status(401).json({ ok: false, error: "Password salah" });

    const roleRes = await pool.query("SELECT PermissionsJson FROM Roles WHERE Role = $1", [user.role]);
    const permissions = roleRes.rows[0].permissionsjson;

    const token = jwt.sign({ userId: user.userid, username: user.username, role: user.role, permissions }, process.env.JWT_SECRET, { expiresIn: "12h" });
    
    await pool.query("UPDATE Users SET LastLoginAt = CURRENT_TIMESTAMP WHERE UserId = $1", [user.userid]);

    res.json({ ok: true, data: { token, user: { UserId: user.userid, Name: user.name, Role: user.role, permissions } } });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// 2. SCAN PATROL (DENGAN GEOFENCING)
app.post("/api/scan", authenticateToken, requirePermission("scan.create"), async (req, res) => {
  const { barcode, lat, lng } = req.body;
  try {
    const cpRes = await pool.query("SELECT * FROM Checkpoints WHERE BarcodeValue = $1 AND Active = TRUE", [barcode]);
    if (cpRes.rows.length === 0) return res.status(404).json({ ok: false, error: "QR tidak valid" });

    const cp = cpRes.rows[0];
    const R = 6371e3;
    const p1 = (lat * Math.PI) / 180, p2 = (cp.latitude * Math.PI) / 180;
    const dp = ((cp.latitude - lat) * Math.PI) / 180, dl = ((cp.longitude - lng) * Math.PI) / 180;
    const a = Math.sin(dp / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin(dl / 2) ** 2;
    const distance = R * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));

    const status = distance <= cp.radiusmeters ? "SUCCESS" : "REJECTED";
    const notes = status === "SUCCESS" ? "" : `Diluar radius (${Math.round(distance)}m)`;

    await pool.query(`INSERT INTO PatrolLogs (UserId, Username, CheckpointId, BarcodeValue, ScanLat, ScanLng, DistanceMeters, Result, Notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, 
    [req.user.userId, req.user.username, cp.checkpointid, barcode, lat, lng, Math.round(distance), status, notes]);

    res.json({ ok: true, data: { status, distance: Math.round(distance) } });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// 3. REKAP BULANAN (DATA JSON UNTUK PDF FRONTEND)
app.get("/api/reports/monthly", authenticateToken, async (req, res) => {
  const { month, year } = req.query;
  try {
    const query = `
      WITH RECURSIVE hours AS (
        SELECT 0 AS start_hour UNION ALL SELECT start_hour + 2 FROM hours WHERE start_hour < 22
      ),
      days AS (
        SELECT generate_series(date_trunc('month', make_date($2, $1, 1)), (date_trunc('month', make_date($2, $1, 1)) + interval '1 month' - interval '1 day'), interval '1 day')::date AS date
      )
      SELECT TO_CHAR(d.date, 'DD/MM/YYYY') as tanggal, h.start_hour || ':00 - ' || (h.start_hour + 2) || ':00' AS window, c.Name AS lokasi, COALESCE(l.Username, '-') AS petugas, CASE WHEN l.LogId IS NULL THEN 'ABSENT' ELSE 'OK' END AS status
      FROM days d CROSS JOIN hours h CROSS JOIN Checkpoints c
      LEFT JOIN PatrolLogs l ON l.CheckpointId = c.CheckpointId AND l.Timestamp::date = d.date AND EXTRACT(HOUR FROM l.Timestamp) >= h.start_hour AND EXTRACT(HOUR FROM l.Timestamp) < (h.start_hour + 2)
      ORDER BY d.date ASC, h.start_hour ASC, c.Name ASC;
    `;
    const result = await pool.query(query, [parseInt(month), parseInt(year)]);
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// 4. USERS & CHECKPOINTS READ
app.get("/api/users", authenticateToken, requirePermission("users.read"), async (req, res) => {
  const result = await pool.query("SELECT UserId, Name, Username, Role, IsActive FROM Users ORDER BY CreatedAt DESC");
  res.json({ ok: true, data: result.rows });
});

app.get("/api/checkpoints", authenticateToken, async (req, res) => {
  const result = await pool.query("SELECT * FROM Checkpoints ORDER BY Name ASC");
  res.json({ ok: true, data: result.rows });
});

// ==========================================
// STATIC FILES & VERCEL ROUTING
// ==========================================

// Sajikan folder public
app.use(express.static(path.join(__dirname, "public")));

// Fallback untuk SPA (Single Page Application)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Jalankan server
const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}

module.exports = app;