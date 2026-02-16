require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");

const app = express();

console.log("🔥 BACKEND CTI AKTIF 🔥");

// ================= CORS (WAJIB UNTUK FRONTEND CPANEL) =================
app.use(
  cors({
    origin: [
      "https://magang.lpkcti.com",
      "http://magang.lpkcti.com",
      "http://localhost:3000",
      "http://127.0.0.1:5500",
    ],
    credentials: true,
  }),
);

app.use(express.json());

// ================= ROOT ROUTE (BIAR RAILWAY TAU SERVER HIDUP) =================
app.get("/", (req, res) => {
  res.send("API LPK CTI RUNNING");
});

// ==========================================================
// 1. KONFIGURASI DATABASE
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
    queueLimit: 0,
  })
  .promise();

console.log(`✅ Mencoba konek ke Database: ${process.env.DB_NAME}`);

// ==========================================================
// 2. KONFIGURASI UPLOAD (AMAN UNTUK RAILWAY)
// ==========================================================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname),
    );
  },
});

const upload = multer({ storage: storage });

app.use("/uploads", express.static(uploadDir));

// ==========================================================
// 3. ROUTES API
// ==========================================================

// ---------- LOGIN ----------
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    if (rows.length === 0)
      return res.status(401).json({ error: "Username tidak ditemukan!" });

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword && user.password !== password) {
      return res.status(401).json({ error: "Password salah!" });
    }

    res.json({
      message: "Login berhasil!",
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

// ---------- REGISTER ----------
app.post("/register", async (req, res) => {
  const { nama_lengkap, nim, jurusan, no_hp, username, password } = req.body;
  try {
    const [cek] = await pool.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    if (cek.length > 0)
      return res.status(400).json({ error: "Username sudah dipakai!" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const [result] = await pool.query(
      "INSERT INTO users (nama_lengkap, nim, jurusan, no_hp, username, password, role, status_laporan) VALUES (?, ?, ?, ?, ?, ?, 'peserta', 'locked')",
      [nama_lengkap, nim, jurusan, no_hp, username, hashedPassword],
    );

    res.json({ id: result.insertId, username });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------- CRUD USER ----------
app.get("/users/:role", async (req, res) => {
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

app.post("/users", async (req, res) => {
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
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const [result] = await pool.query(
      "INSERT INTO users (nama_lengkap, nim, jurusan, no_hp, username, password, role, status_laporan, company_id) VALUES (?, ?, ?, ?, ?, ?, ?, 'locked', ?)",
      [
        nama_lengkap,
        nim || null,
        jurusan || null,
        no_hp || null,
        username,
        hashedPassword,
        role,
        company_id || null,
      ],
    );

    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/users/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id = ?", [req.params.id]);
    res.json({ message: "User dihapus" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------- COMPANIES ----------
app.get("/companies", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM companies ORDER BY id DESC");
    res.json(rows);
  } catch (e) {
    res.status(500).json(e);
  }
});

// ---------- PLACEMENTS ----------
app.get("/placements", async (req, res) => {
  try {
    const q = `SELECT p.id, p.user_id, p.supervisor_id, p.company_id, u1.nama_lengkap as peserta, u1.nim, u1.jurusan, u1.no_hp, u1.foto_profil, u2.nama_lengkap as supervisor, c.nama_perusahaan
               FROM placements p
               JOIN users u1 ON p.user_id = u1.id
               JOIN users u2 ON p.supervisor_id = u2.id
               JOIN companies c ON p.company_id = c.id`;

    const [rows] = await pool.query(q);
    res.json(rows);
  } catch (e) {
    res.status(500).json(e);
  }
});

// ---------- LOGBOOK ----------
app.post("/logbook", upload.single("bukti_foto"), async (req, res) => {
  try {
    const { user_id, kegiatan, tanggal, kehadiran } = req.body;
    const bukti_foto = req.file ? req.file.filename : null;
    const statusHadir = kehadiran || "Hadir";

    const [result] = await pool.query(
      "INSERT INTO logbooks (user_id, tanggal, kegiatan, bukti_foto, status, kehadiran) VALUES (?, ?, ?, ?, 'menunggu', ?)",
      [user_id, tanggal, kegiatan, bukti_foto, statusHadir],
    );

    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/logbook/:userId", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM logbooks WHERE user_id = ? ORDER BY tanggal DESC",
      [req.params.userId],
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json(e);
  }
});

// ---------- ADMIN STATS ----------
app.get("/admin/stats", async (req, res) => {
  try {
    const queries = [
      pool.query("SELECT COUNT(*) as count FROM users WHERE role = 'peserta'"),
      pool.query(
        "SELECT COUNT(*) as count FROM users WHERE role = 'supervisor'",
      ),
      pool.query("SELECT COUNT(*) as count FROM logbooks"),
      pool.query("SELECT COUNT(*) as count FROM evaluations"),
      pool.query("SELECT COUNT(*) as count FROM companies"),
      pool.query("SELECT COUNT(*) as count FROM placements"),
    ];

    const results = await Promise.all(queries);

    res.json({
      total_peserta: results[0][0][0].count,
      total_supervisor: results[1][0][0].count,
      total_logbooks: results[2][0][0].count,
      total_lulus: results[3][0][0].count,
      total_perusahaan: results[4][0][0].count,
      total_placed: results[5][0][0].count,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ERROR HANDLER (BIAR RAILWAY GAK MATI) =================
process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT EXCEPTION:", err);
});

process.on("unhandledRejection", (err) => {
  console.error("UNHANDLED REJECTION:", err);
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

