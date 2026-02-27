// ==========================================
// File: server.js (Node.js Enterprise Backend)
// ==========================================
require('dotenv').config();
const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
// Menggunakan path absolut agar Vercel tidak kebingungan
app.use(express.static(path.join(__dirname, 'public')));

// Rute khusus untuk memanggil index.html saat web pertama kali dibuka
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- KONEKSI DATABASE POSTGRESQL ---
// Menggunakan URL koneksi dari Supabase/Neon
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Wajib untuk Supabase/Neon
  }
});

// ==========================================
// MIDDLEWARE (KEAMANAN & HAK AKSES)
// ==========================================

// 1. Verifikasi Token JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ ok: false, error: 'Silakan login terlebih dahulu' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ ok: false, error: 'Sesi Anda telah berakhir, silakan login ulang' });
    req.user = user;
    next();
  });
};

// 2. Verifikasi Hak Akses (Role Based Access Control)
const requirePermission = (permission) => {
  return (req, res, next) => {
    const perms = req.user.permissions || [];
    if (perms.includes('all') || perms.includes(permission) || perms.includes(permission.split('.')[0] + '.*')) {
      next();
    } else {
      res.status(403).json({ ok: false, error: 'Akses ditolak: Anda tidak memiliki izin untuk tindakan ini' });
    }
  };
};

// ==========================================
// API AUTHENTICATION & SESSION
// ==========================================

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userRes = await pool.query('SELECT * FROM Users WHERE Username = $1 AND IsActive = TRUE', [username]);
    if (userRes.rows.length === 0) return res.status(401).json({ ok: false, error: 'Username tidak ditemukan atau non-aktif' });
    
    const user = userRes.rows[0];
    const valid = await bcrypt.compare(password, user.passwordhash);
    if (!valid) return res.status(401).json({ ok: false, error: 'Password salah' });

    const roleRes = await pool.query('SELECT PermissionsJson FROM Roles WHERE Role = $1', [user.role]);
    const permissions = roleRes.rows[0].permissionsjson;

    const token = jwt.sign({ userId: user.userid, username: user.username, role: user.role, permissions }, process.env.JWT_SECRET, { expiresIn: '12h' });
    await pool.query('UPDATE Users SET LastLoginAt = CURRENT_TIMESTAMP WHERE UserId = $1', [user.userid]);

    res.json({ ok: true, data: { token, user: { UserId: user.userid, Name: user.name, Role: user.role, permissions } } });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT UserId, Name, Username, Role FROM Users WHERE UserId = $1 AND IsActive = TRUE', [req.user.userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ ok: false });
    const user = userRes.rows[0];
    user.permissions = req.user.permissions;
    res.json({ ok: true, data: user });
  } catch(err) { res.status(500).json({ ok: false }); }
});

// ==========================================
// API CORE: SCAN PATROL
// ==========================================

app.post('/api/scan', authenticateToken, requirePermission('scan.create'), async (req, res) => {
  const { barcode, lat, lng } = req.body;
  try {
    const cpRes = await pool.query('SELECT * FROM Checkpoints WHERE BarcodeValue = $1 AND Active = TRUE', [barcode]);
    if (cpRes.rows.length === 0) return res.status(404).json({ ok: false, error: 'QR Code tidak dikenali atau Checkpoint sedang non-aktif' });
    
    const cp = cpRes.rows[0];
    
    // Kalkulasi Jarak Haversine (Sistem Geofencing)
    const R = 6371e3; 
    const p1 = lat * Math.PI/180, p2 = cp.latitude * Math.PI/180;
    const dp = (cp.latitude-lat) * Math.PI/180, dl = (cp.longitude-lng) * Math.PI/180;
    const a = Math.sin(dp/2) * Math.sin(dp/2) + Math.cos(p1) * Math.cos(p2) * Math.sin(dl/2) * Math.sin(dl/2);
    const distance = R * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)));

    const isWithinRadius = distance <= cp.radiusmeters;
    const resultStatus = isWithinRadius ? 'SUCCESS' : 'REJECTED';
    const notes = isWithinRadius ? '' : `Diluar radius (${Math.round(distance)}m > ${cp.radiusmeters}m)`;

    // Simpan ke database log
    await pool.query(
      `INSERT INTO PatrolLogs (UserId, Username, CheckpointId, BarcodeValue, ScanLat, ScanLng, DistanceMeters, Result, Notes) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [req.user.userId, req.user.username, cp.checkpointid, barcode, lat, lng, Math.round(distance), resultStatus, notes]
    );

    if (resultStatus === 'SUCCESS') {
      res.json({ ok: true, data: { status: resultStatus, distance: Math.round(distance) } });
    } else {
      res.status(400).json({ ok: false, error: 'Scan ditolak: ' + notes });
    }
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ==========================================
// API CRUD: USERS
// ==========================================

app.get('/api/users', authenticateToken, requirePermission('users.read'), async (req, res) => {
  try {
    const result = await pool.query('SELECT UserId, Name, Username, Role, IsActive, CreatedAt, LastLoginAt FROM Users ORDER BY CreatedAt DESC');
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.post('/api/users', authenticateToken, requirePermission('users.write'), async (req, res) => {
  const { Name, Username, Password, Role, IsActive } = req.body;
  try {
    const hashedPass = await bcrypt.hash(Password, 10);
    await pool.query(
      'INSERT INTO Users (Name, Username, PasswordHash, Role, IsActive) VALUES ($1, $2, $3, $4, $5)',
      [Name, Username, hashedPass, Role, IsActive]
    );
    res.json({ ok: true });
  } catch (err) { 
    if(err.code === '23505') return res.status(400).json({ ok: false, error: 'Username sudah digunakan' });
    res.status(500).json({ ok: false, error: err.message }); 
  }
});

app.put('/api/users', authenticateToken, requirePermission('users.write'), async (req, res) => {
  const { UserId, Name, Password, Role, IsActive } = req.body;
  try {
    if (Password) { // Jika password diisi, update dengan password baru
      const hashedPass = await bcrypt.hash(Password, 10);
      await pool.query(
        'UPDATE Users SET Name=$1, PasswordHash=$2, Role=$3, IsActive=$4, UpdatedAt=CURRENT_TIMESTAMP WHERE UserId=$5',
        [Name, hashedPass, Role, IsActive, UserId]
      );
    } else { // Jika password kosong, jangan ubah passwordnya
      await pool.query(
        'UPDATE Users SET Name=$1, Role=$2, IsActive=$3, UpdatedAt=CURRENT_TIMESTAMP WHERE UserId=$4',
        [Name, Role, IsActive, UserId]
      );
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ==========================================
// API CRUD: CHECKPOINTS
// ==========================================

app.get('/api/checkpoints', authenticateToken, requirePermission('checkpoints.read'), async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM Checkpoints ORDER BY CreatedAt DESC');
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.post('/api/checkpoints', authenticateToken, requirePermission('checkpoints.write'), async (req, res) => {
  const { Name, BarcodeValue, Latitude, Longitude, RadiusMeters, Active } = req.body;
  try {
    await pool.query(
      'INSERT INTO Checkpoints (Name, BarcodeValue, Latitude, Longitude, RadiusMeters, Active) VALUES ($1, $2, $3, $4, $5, $6)',
      [Name, BarcodeValue, Latitude, Longitude, RadiusMeters, Active]
    );
    res.json({ ok: true });
  } catch (err) { 
    if(err.code === '23505') return res.status(400).json({ ok: false, error: 'Barcode/QR Value sudah digunakan titik lain' });
    res.status(500).json({ ok: false, error: err.message }); 
  }
});

app.put('/api/checkpoints', authenticateToken, requirePermission('checkpoints.write'), async (req, res) => {
  const { CheckpointId, Name, BarcodeValue, Latitude, Longitude, RadiusMeters, Active } = req.body;
  try {
    await pool.query(
      'UPDATE Checkpoints SET Name=$1, BarcodeValue=$2, Latitude=$3, Longitude=$4, RadiusMeters=$5, Active=$6, UpdatedAt=CURRENT_TIMESTAMP WHERE CheckpointId=$7',
      [Name, BarcodeValue, Latitude, Longitude, RadiusMeters, Active, CheckpointId]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ==========================================
// API: PATROL LOGS & SCHEDULES
// ==========================================

app.get('/api/patrollogs', authenticateToken, requirePermission('logs.read'), async (req, res) => {
  try {
    // Menampilkan 200 data log terbaru agar server tidak berat
    const result = await pool.query('SELECT LogId, Timestamp, Username, BarcodeValue, DistanceMeters, Result, Notes FROM PatrolLogs ORDER BY Timestamp DESC LIMIT 200');
    res.json({ ok: true, data: result.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.get('/api/schedules', authenticateToken, requirePermission('schedules.read'), async (req, res) => {
  // Placeholder untuk jadwal jika Anda ingin mengembangkannya nanti
  res.json({ ok: true, data: [] }); 
});

// ==========================================
// JALANKAN SERVER
// ==========================================
// ==========================================
// JALANKAN SERVER & EXPORT UNTUK VERCEL
// ==========================================
const PORT = process.env.PORT || 3000;

// Jalankan server untuk mode lokal
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`🚀 Server berjalan di http://localhost:${PORT}`));
}

// BARIS INI SANGAT WAJIB UNTUK VERCEL:
module.exports = app;

// --- ENDPOINT REKAP BULANAN ---
app.get('/api/reports/monthly', authenticateToken, async (req, res) => {
  const { month, year } = req.query;

  try {
    const query = `
      WITH RECURSIVE hours AS (
        SELECT 0 AS start_hour UNION ALL SELECT start_hour + 2 FROM hours WHERE start_hour < 22
      ),
      days AS (
        SELECT generate_series(
          date_trunc('month', make_date($2, $1, 1)),
          (date_trunc('month', make_date($2, $1, 1)) + interval '1 month' - interval '1 day'),
          interval '1 day'
        )::date AS date
      )
      SELECT 
        TO_CHAR(d.date, 'DD/MM/YYYY') as tanggal,
        h.start_hour || ':00 - ' || (h.start_hour + 2) || ':00' AS window,
        c.Name AS lokasi,
        COALESCE(l.Username, '-') AS petugas,
        CASE WHEN l.LogId IS NULL THEN 'ABSENT' ELSE 'OK' END AS status
      FROM days d
      CROSS JOIN hours h
      CROSS JOIN Checkpoints c
      LEFT JOIN PatrolLogs l ON 
        l.CheckpointId = c.CheckpointId AND 
        l.Timestamp::date = d.date AND
        EXTRACT(HOUR FROM l.Timestamp) >= h.start_hour AND 
        EXTRACT(HOUR FROM l.Timestamp) < (h.start_hour + 2)
      ORDER BY d.date ASC, h.start_hour ASC, c.Name ASC;
    `;

    const result = await pool.query(query, [parseInt(month), parseInt(year)]);
    res.json({ ok: true, data: result.rows }); // Hanya mengirim data mentah (JSON)

  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Memaksa Vercel mengambil versi Server dan mengatasi masalah format bundler
let PdfPrinter = require('pdfmake/src/printer');
if (typeof PdfPrinter !== 'function' && PdfPrinter.default) {
  PdfPrinter = PdfPrinter.default;
}

// Font standar untuk PDF
const fonts = {
  Roboto: {
    normal: 'Helvetica',
    bold: 'Helvetica-Bold',
    italics: 'Helvetica-Oblique',
    bolditalics: 'Helvetica-BoldOblique'
  }
};
const printer = new PdfPrinter(fonts);

app.get('/api/reports/pdf', authenticateToken, async (req, res) => {
  const { month, year } = req.query;

  try {
    // Query untuk mendapatkan semua jadwal yang seharusnya vs kenyataan log
    const query = `
      WITH RECURSIVE hours AS (
        SELECT 0 AS start_hour UNION ALL SELECT start_hour + 2 FROM hours WHERE start_hour < 22
      ),
      days AS (
        SELECT generate_series(
          date_trunc('month', make_date($2, $1, 1)),
          (date_trunc('month', make_date($2, $1, 1)) + interval '1 month' - interval '1 day'),
          interval '1 day'
        )::date AS date
      )
      SELECT 
        TO_CHAR(d.date, 'DD/MM/YYYY') as tanggal,
        h.start_hour || ':00 - ' || (h.start_hour + 2) || ':00' AS window,
        c.Name AS lokasi,
        COALESCE(l.Username, '-') AS petugas,
        CASE WHEN l.LogId IS NULL THEN 'ABSENT' ELSE 'OK' END AS status
      FROM days d
      CROSS JOIN hours h
      CROSS JOIN Checkpoints c
      LEFT JOIN PatrolLogs l ON 
        l.CheckpointId = c.CheckpointId AND 
        l.Timestamp::date = d.date AND
        EXTRACT(HOUR FROM l.Timestamp) >= h.start_hour AND 
        EXTRACT(HOUR FROM l.Timestamp) < (h.start_hour + 2)
      ORDER BY d.date ASC, h.start_hour ASC, c.Name ASC;
    `;

    const result = await pool.query(query, [parseInt(month), parseInt(year)]);
    
    // Struktur Dokumen PDF
    const docDefinition = {
      content: [
        { text: `LAPORAN REKAP PATROLI BULANAN`, style: 'header' },
        { text: `Periode: ${month}/${year}`, style: 'subheader' },
        {
          table: {
            headerRows: 1,
            widths: ['auto', 'auto', '*', 'auto', 'auto'],
            body: [
              [
                { text: 'Tanggal', style: 'tableHeader' },
                { text: 'Waktu', style: 'tableHeader' },
                { text: 'Titik Lokasi', style: 'tableHeader' },
                { text: 'Petugas', style: 'tableHeader' },
                { text: 'Status', style: 'tableHeader' }
              ],
              ...result.rows.map(row => [
                row.tanggal,
                row.window,
                row.lokasi,
                row.petugas,
                { text: row.status, color: row.status === 'ABSENT' ? 'red' : 'green', bold: row.status === 'ABSENT' }
              ])
            ]
          }
        }
      ],
      styles: {
        header: { fontSize: 18, bold: true, alignment: 'center', margin: [0, 0, 0, 10] },
        subheader: { fontSize: 12, alignment: 'center', margin: [0, 0, 0, 20] },
        tableHeader: { bold: true, fontSize: 11, color: 'black', fillColor: '#eeeeee' }
      }
    };

    const pdfDoc = printer.createPdfKitDocument(docDefinition);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=Laporan-Patroli-${month}-${year}.pdf`);
    pdfDoc.pipe(res);
    pdfDoc.end();

  } catch (err) {
    res.status(500).send(err.message);
  }
});