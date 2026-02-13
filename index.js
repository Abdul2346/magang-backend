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
// ROUTER PREFIX /api
// ==========================================================
const router = express.Router();
app.use("/api", router);

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

console.log("DB:", process.env.DB_NAME);

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

router.use("/uploads", express.static(uploadDir));

// ==========================================================
// AUTH
// ==========================================================
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE username=?", [
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

router.post("/register", async (req, res) => {
  const { nama_lengkap, nim, jurusan, no_hp, username, password } = req.body;
  try {
    const [cek] = await pool.query("SELECT id FROM users WHERE username=?", [
      username,
    ]);
    if (cek.length > 0)
      return res.status(400).json({ error: "Username sudah dipakai!" });

    const hashed = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      `INSERT INTO users (nama_lengkap,nim,jurusan,no_hp,username,password,role,status_laporan)
       VALUES (?,?,?,?,?,?,'peserta','locked')`,
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
router.get("/users/:role", async (req, res) => {
  const [rows] = await pool.query(
    "SELECT * FROM users WHERE role=? ORDER BY id DESC",
    [req.params.role],
  );
  res.json(rows);
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
  const hashed = await bcrypt.hash(password, 10);

  const [result] = await pool.query(
    `INSERT INTO users (nama_lengkap,nim,jurusan,no_hp,username,password,role,status_laporan,company_id)
     VALUES (?,?,?,?,?,?,?,'locked',?)`,
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
});

router.put("/users/:id", async (req, res) => {
  const id = req.params.id;
  const data = req.body;

  let query = `UPDATE users SET nama_lengkap=?,nim=?,jurusan=?,no_hp=?,username=?,role=?,company_id=?`;
  let values = [
    data.nama_lengkap,
    data.nim || null,
    data.jurusan || null,
    data.no_hp || null,
    data.username,
    data.role,
    data.company_id || null,
  ];

  if (data.password) {
    const hashed = await bcrypt.hash(data.password, 10);
    query += `, password=?`;
    values.push(hashed);
  }

  values.push(id);
  await pool.query(query + " WHERE id=?", values);
  res.json({ message: "updated" });
});

router.delete("/users/:id", async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=?", [req.params.id]);
  res.json({ message: "deleted" });
});

// ==========================================================
// COMPANIES
// ==========================================================
router.get("/companies", async (req, res) => {
  const [rows] = await pool.query("SELECT * FROM companies ORDER BY id DESC");
  res.json(rows);
});

router.post("/companies", async (req, res) => {
  const { nama_perusahaan, alamat, kontak } = req.body;
  await pool.query(
    "INSERT INTO companies (nama_perusahaan,alamat,kontak) VALUES (?,?,?)",
    [nama_perusahaan, alamat, kontak],
  );
  res.json({ message: "added" });
});

router.put("/companies/:id", async (req, res) => {
  const { nama_perusahaan, alamat, kontak } = req.body;
  await pool.query(
    "UPDATE companies SET nama_perusahaan=?,alamat=?,kontak=? WHERE id=?",
    [nama_perusahaan, alamat, kontak, req.params.id],
  );
  res.json({ message: "updated" });
});

router.delete("/companies/:id", async (req, res) => {
  await pool.query("DELETE FROM companies WHERE id=?", [req.params.id]);
  res.json({ message: "deleted" });
});

// ==========================================================
// PLACEMENTS
// ==========================================================
router.get("/placements", async (req, res) => {
  const [rows] = await pool.query(`
    SELECT p.id,u.nama_lengkap as peserta,u.nim,u.jurusan,
           s.nama_lengkap as supervisor,c.nama_perusahaan,
           p.user_id,p.supervisor_id,p.company_id
    FROM placements p
    JOIN users u ON p.user_id=u.id
    JOIN users s ON p.supervisor_id=s.id
    JOIN companies c ON p.company_id=c.id
    ORDER BY p.id DESC`);
  res.json(rows);
});

router.post("/placements", async (req, res) => {
  const { user_id, supervisor_id, company_id } = req.body;
  await pool.query(
    "INSERT INTO placements (user_id,supervisor_id,company_id) VALUES (?,?,?)",
    [user_id, supervisor_id, company_id],
  );
  res.json({ message: "added" });
});

router.put("/placements/:id", async (req, res) => {
  const { user_id, supervisor_id, company_id } = req.body;
  await pool.query(
    "UPDATE placements SET user_id=?,supervisor_id=?,company_id=? WHERE id=?",
    [user_id, supervisor_id, company_id, req.params.id],
  );
  res.json({ message: "updated" });
});

router.delete("/placements/:id", async (req, res) => {
  await pool.query("DELETE FROM placements WHERE id=?", [req.params.id]);
  res.json({ message: "deleted" });
});

// ==========================================================
// LOGBOOK
// ==========================================================
router.post("/logbook", upload.single("bukti_foto"), async (req, res) => {
  const { user_id, kegiatan, tanggal } = req.body;
  const bukti = req.file ? req.file.filename : null;

  const [r] = await pool.query(
    "INSERT INTO logbooks (user_id,tanggal,kegiatan,bukti_foto,status) VALUES (?,?,?,?, 'menunggu')",
    [user_id, tanggal, kegiatan, bukti],
  );
  res.json({ id: r.insertId });
});

router.get("/logbook/:userId", async (req, res) => {
  const [rows] = await pool.query(
    "SELECT * FROM logbooks WHERE user_id=? ORDER BY tanggal DESC",
    [req.params.userId],
  );
  res.json(rows);
});

router.put("/logbook-status/:id", async (req, res) => {
  await pool.query("UPDATE logbooks SET status=? WHERE id=?", [
    req.body.status,
    req.params.id,
  ]);
  res.json({ message: "updated" });
});

router.delete("/logbook/:id", async (req, res) => {
  await pool.query("DELETE FROM logbooks WHERE id=?", [req.params.id]);
  res.json({ message: "deleted" });
});

// ==========================================================
// ADMIN STATS
// ==========================================================
router.get("/admin/stats", async (req, res) => {
  const [[peserta]] = await pool.query(
    "SELECT COUNT(*) as c FROM users WHERE role='peserta'",
  );
  const [[supervisor]] = await pool.query(
    "SELECT COUNT(*) as c FROM users WHERE role='supervisor'",
  );
  const [[logbooks]] = await pool.query("SELECT COUNT(*) as c FROM logbooks");
  const [[companies]] = await pool.query("SELECT COUNT(*) as c FROM companies");
  const [[placed]] = await pool.query("SELECT COUNT(*) as c FROM placements");

  res.json({
    total_peserta: peserta.c,
    total_supervisor: supervisor.c,
    total_logbooks: logbooks.c,
    total_perusahaan: companies.c,
    total_placed: placed.c,
    total_lulus: 0,
  });
});

// ==========================================================
app.get("/", (req, res) => res.send("API MAGANG RUNNING 🚀"));
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => console.log("Server running", PORT));
