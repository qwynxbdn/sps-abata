// File: fix-db.js
require('dotenv').config();
const { Client } = require('pg');

async function fixDatabase() {
  console.log('Menambal (Patching) Database...');
  const client = new Client({
    user: process.env.DB_USER, 
    host: process.env.DB_HOST,
    password: process.env.DB_PASSWORD, 
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
  });

  try {
    await client.connect();

    // 1. Tambahkan kolom ke tabel Checkpoints
    await client.query('ALTER TABLE Checkpoints ADD COLUMN IF NOT EXISTS CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP;');
    await client.query('ALTER TABLE Checkpoints ADD COLUMN IF NOT EXISTS UpdatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP;');
    console.log('✅ Kolom CreatedAt & UpdatedAt berhasil ditambahkan ke tabel Checkpoints.');

    // 2. Tambahkan kolom ke tabel Users (agar tidak error saat update user)
    await client.query('ALTER TABLE Users ADD COLUMN IF NOT EXISTS UpdatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP;');
    console.log('✅ Kolom UpdatedAt berhasil ditambahkan ke tabel Users.');

  } catch (err) {
    console.error('❌ Terjadi kesalahan:', err.message);
  } finally {
    await client.end();
    console.log('Selesai! Silakan jalankan kembali server Anda.');
  }
}

fixDatabase();