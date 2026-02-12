require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");

const app = express();

// ======================= CORS =======================
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  }),
);

app.use(express.json());

// ==========================================================
// DATABASE
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

(async () => {
  try {
    await pool.query("SELECT 1");
    console.log("✅ Database connected");
  } catch (err) {
    console.error("❌ Database gagal connect:", err.message);
  }
})();

// ==========================================================
// UPLOAD
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
// AUTH
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
// USERS
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

// ==========================================================
// LOGBOOK
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

// ==========================================================
// HEALTH CHECK (penting buat Railway)
// ==========================================================
app.get("/", (req, res) => {
  res.send("API MAGANG RUNNING 🚀");
});

// ==========================================================
// START SERVER (WAJIB pakai PORT railway)
// ==========================================================
const PORT = process.env.PORT || 8080;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
