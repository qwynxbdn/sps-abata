// File: setup.js
require('dotenv').config();
const { Client } = require('pg');
const bcrypt = require('bcrypt');

async function setup() {
  console.log('Memulai setup database...');
  
  // 1. Konek ke database bawaan (postgres) untuk membuat database baru
  const clientInitial = new Client({
    user: process.env.DB_USER, host: process.env.DB_HOST,
    password: process.env.DB_PASSWORD, port: process.env.DB_PORT,
    database: 'postgres'
  });

  await clientInitial.connect();
  try {
    await clientInitial.query(`CREATE DATABASE ${process.env.DB_NAME}`);
    console.log(`Database ${process.env.DB_NAME} berhasil dibuat.`);
  } catch (err) {
    if (err.code === '42P04') console.log(`Database ${process.env.DB_NAME} sudah ada.`);
    else throw err;
  }
  await clientInitial.end();

  // 2. Konek ke database patrol_db untuk membuat tabel
  const client = new Client({
    user: process.env.DB_USER, host: process.env.DB_HOST,
    password: process.env.DB_PASSWORD, port: process.env.DB_PORT,
    database: process.env.DB_NAME
  });

  await client.connect();
  
  // Buat Ekstensi UUID & Tabel
  const queries = `
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    CREATE TABLE IF NOT EXISTS Roles (
      Role VARCHAR(50) PRIMARY KEY, PermissionsJson JSONB NOT NULL, Description TEXT
    );

    CREATE TABLE IF NOT EXISTS Users (
      UserId UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      Name VARCHAR(100) NOT NULL, Username VARCHAR(50) UNIQUE NOT NULL,
      PasswordHash VARCHAR(255) NOT NULL, Role VARCHAR(50) REFERENCES Roles(Role),
      IsActive BOOLEAN DEFAULT TRUE, Phone VARCHAR(20),
      CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP, LastLoginAt TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS Checkpoints (
      CheckpointId UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      Name VARCHAR(100) NOT NULL, BarcodeValue VARCHAR(100) UNIQUE NOT NULL,
      Latitude DECIMAL(10, 8) NOT NULL, Longitude DECIMAL(11, 8) NOT NULL,
      RadiusMeters DECIMAL(5, 2) DEFAULT 50, Active BOOLEAN DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS PatrolLogs (
      LogId UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      Timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UserId UUID REFERENCES Users(UserId), Username VARCHAR(50),
      CheckpointId UUID REFERENCES Checkpoints(CheckpointId),
      BarcodeValue VARCHAR(100), ScanLat DECIMAL(10, 8), ScanLng DECIMAL(11, 8),
      DistanceMeters DECIMAL(8, 2), Result VARCHAR(20), Notes TEXT
    );
  `;
  await client.query(queries);
  console.log('Semua tabel berhasil dibuat.');

  // 3. Insert Default Role & Super Admin (OOPSv1)
  await client.query(`INSERT INTO Roles (Role, PermissionsJson, Description) VALUES 
    ('Admin', '["all"]', 'System Administrator'),
    ('Guard', '["scan.create"]', 'Security Guard') ON CONFLICT DO NOTHING`);

  const checkAdmin = await client.query(`SELECT * FROM Users WHERE Username = 'admin'`);
  if (checkAdmin.rows.length === 0) {
    const hashedPass = await bcrypt.hash('OOPSv1', 10);
    await client.query(`INSERT INTO Users (Name, Username, PasswordHash, Role) VALUES ('Super Admin', 'admin', $1, 'Admin')`, [hashedPass]);
    console.log('User Admin berhasil dibuat. (Username: admin | Pass: OOPSv1)');
  }

  await client.end();
  console.log('Setup Selesai!');
}

setup().catch(console.error);