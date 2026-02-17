require("dotenv").config();
const express = require("express");
const mysql = require("mysql2"); // Ganti pg ke mysql2
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");

const app = express();

// ================= CORS =================
app.use(
  cors({
    origin: ["http://localhost:5173", "https://magang.lpkcti.com"],
    credentials: true,
  }),
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ================= TEST ROUTE =================
app.get("/", (req, res) => {
  res.send("API MAGANG LPK CTI AKTIF 🚀");
});

const router = express.Router();
app.use("/api", router);

// ==========================================================
// 1. KONFIGURASI DATABASE (MYSQL VERSION)
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
// 2. KONFIGURASI UPLOAD
// ==========================================================

// PATH ABSOLUTE FOLDER DOMAIN
const uploadDir = "/home/USERNAME/public_html/magang.lpkcti.com/uploads";

// bikin folder kalau belum ada
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname),
    );
  },
});

const upload = multer({ storage });

// static access dari domain
app.use("/api/uploads", express.static(uploadDir));

// ==========================================================
// 3. ROUTES API (MYSQL SYNTAX)
// ==========================================================

router.post("/login", async (req, res) => {
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

router.post("/register", async (req, res) => {
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

// --- B. CRUD USER ---
router.get("/users/:role", async (req, res) => {
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

router.post("/users", async (req, res) => {
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

router.delete("/users/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id = ?", [req.params.id]);
    res.json({ message: "User dihapus" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- C. PERUSAHAAN ---
router.get("/companies", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM companies ORDER BY id DESC");
    res.json(rows);
  } catch (e) {
    res.status(500).json(e);
  }
});

// --- D. PLACEMENT ---
router.get("/placements", async (req, res) => {
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

// --- E. LOGBOOK ---

// CREATE
router.post("/logbook", upload.single("bukti_foto"), async (req, res) => {
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

// READ by user
router.get("/logbook/:userId", async (req, res) => {
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

// UPDATE isi logbook
router.put("/logbook/:id", upload.single("bukti_foto"), async (req, res) => {
  try {
    const { tanggal, kegiatan } = req.body;
    const id = req.params.id;

    if (req.file) {
      await pool.query(
        "UPDATE logbooks SET tanggal=?, kegiatan=?, bukti_foto=? WHERE id=?",
        [tanggal, kegiatan, req.file.filename, id],
      );
    } else {
      await pool.query("UPDATE logbooks SET tanggal=?, kegiatan=? WHERE id=?", [
        tanggal,
        kegiatan,
        id,
      ]);
    }

    res.json({ message: "Logbook diupdate" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE status validasi (approve / reject)
router.put("/logbook-status/:id", async (req, res) => {
  try {
    const { status } = req.body;

    await pool.query("UPDATE logbooks SET status=? WHERE id=?", [
      status,
      req.params.id,
    ]);

    res.json({ message: "Status diperbarui" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE
router.delete("/logbook/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM logbooks WHERE id=?", [req.params.id]);
    res.json({ message: "Logbook dihapus" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- G. ADMIN STATS ---
router.get("/admin/stats", async (req, res) => {
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

router.get("/all-logbooks", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT l.*, u.nama_lengkap
      FROM logbooks l
      JOIN users u ON l.user_id = u.id
      ORDER BY l.tanggal DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/all-nilai", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT e.*, u.nama_lengkap
      FROM evaluations e
      JOIN users u ON e.user_id = u.id
      ORDER BY e.created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//GAADA ROUTE SAMASEKALI
router.put("/users/:id", async (req, res) => {
  const id = req.params.id;
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
    let hashedPassword = null;

    if (password) {
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    }

    if (hashedPassword) {
      await pool.query(
        `UPDATE users SET nama_lengkap=?, nim=?, jurusan=?, no_hp=?, username=?, password=?, role=?, company_id=? WHERE id=?`,
        [
          nama_lengkap,
          nim || null,
          jurusan || null,
          no_hp || null,
          username,
          hashedPassword,
          role,
          company_id || null,
          id,
        ],
      );
    } else {
      await pool.query(
        `UPDATE users SET nama_lengkap=?, nim=?, jurusan=?, no_hp=?, username=?, role=?, company_id=? WHERE id=?`,
        [
          nama_lengkap,
          nim || null,
          jurusan || null,
          no_hp || null,
          username,
          role,
          company_id || null,
          id,
        ],
      );
    }

    res.json({ message: "User berhasil diupdate" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
