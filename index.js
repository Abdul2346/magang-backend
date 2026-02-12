require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");

const app = express();
app.use(cors());
app.use(express.json());

// ==========================================================
// 1. DATABASE
// ==========================================================
const pool = mysql
  .createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
  })
  .promise();

console.log(`✅ Database: ${process.env.DB_NAME}`);

// ==========================================================
// 2. UPLOAD
// ==========================================================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + unique + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

app.use("/api/uploads", express.static(uploadDir));

// ==========================================================
// 3. AUTH
// ==========================================================

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    if (rows.length === 0)
      return res.status(401).json({ error: "Username tidak ditemukan!" });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) return res.status(401).json({ error: "Password salah!" });

    res.json({
      message: "Login berhasil",
      user: {
        id: user.id,
        nama: user.nama_lengkap,
        role: user.role,
        foto_profil: user.foto_profil,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/register", async (req, res) => {
  const { nama_lengkap, nim, jurusan, no_hp, username, password } = req.body;

  try {
    const [cek] = await pool.query("SELECT id FROM users WHERE username = ?", [
      username,
    ]);

    if (cek.length > 0)
      return res.status(400).json({ error: "Username sudah dipakai!" });

    const hashed = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      `INSERT INTO users
      (nama_lengkap, nim, jurusan, no_hp, username, password, role, status_laporan)
      VALUES (?, ?, ?, ?, ?, ?, 'peserta', 'locked')`,
      [nama_lengkap, nim, jurusan, no_hp, username, hashed],
    );

    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================================
// 4. USERS
// ==========================================================

app.get("/api/users/:role", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM users WHERE role = ? ORDER BY id DESC",
      [req.params.role],
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/users", async (req, res) => {
  const {
    nama_lengkap,
    nim,
    jurusan,
    no_hp,
    username,
    password,
    role,
    company_id,
  } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      `INSERT INTO users
      (nama_lengkap, nim, jurusan, no_hp, username, password, role, status_laporan, company_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'locked', ?)`,
      [
        nama_lengkap,
        nim || null,
        jurusan || null,
        no_hp || null,
        username,
        hashed,
        role,
        company_id || null,
      ],
    );

    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/users/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id = ?", [req.params.id]);
    res.json({ message: "User dihapus" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================================
// 5. COMPANIES
// ==========================================================

app.get("/api/companies", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM companies ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================================
// 6. LOGBOOK
// ==========================================================

app.post("/api/logbook", upload.single("bukti_foto"), async (req, res) => {
  try {
    const { user_id, kegiatan, tanggal } = req.body;
    const bukti_foto = req.file ? req.file.filename : null;

    const [result] = await pool.query(
      `INSERT INTO logbooks
      (user_id, tanggal, kegiatan, bukti_foto, status)
      VALUES (?, ?, ?, ?, 'menunggu')`,
      [user_id, tanggal, kegiatan, bukti_foto],
    );

    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/logbook/:userId", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM logbooks WHERE user_id = ? ORDER BY tanggal DESC",
      [req.params.userId],
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================================
// 7. ADMIN STATS
// ==========================================================

app.get("/api/admin/stats", async (req, res) => {
  try {
    const queries = [
      pool.query("SELECT COUNT(*) as count FROM users WHERE role='peserta'"),
      pool.query("SELECT COUNT(*) as count FROM users WHERE role='supervisor'"),
      pool.query("SELECT COUNT(*) as count FROM logbooks"),
      pool.query("SELECT COUNT(*) as count FROM companies"),
      pool.query("SELECT COUNT(*) as count FROM placements"),
    ];

    const results = await Promise.all(queries);

    res.json({
      total_peserta: results[0][0][0].count,
      total_supervisor: results[1][0][0].count,
      total_logbooks: results[2][0][0].count,
      total_perusahaan: results[3][0][0].count,
      total_placed: results[4][0][0].count,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
