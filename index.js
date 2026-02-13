require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// ======================= CORS =======================
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  }),
);

app.use(express.json());

// ==========================================================
// ROUTER PREFIX
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
    enableKeepAlive: true,
  })
  .promise();

// ==========================================================
// AUTH MIDDLEWARE
// ==========================================================
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Unauthorized" });
  try {
    const token = auth.split(" ")[1];
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: "Token invalid" });
  }
};

const allow =
  (...roles) =>
  (req, res, next) => {
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: "Akses ditolak" });
    next();
  };

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
  const [rows] = await pool.query("SELECT * FROM users WHERE username=?", [
    username,
  ]);
  if (!rows.length)
    return res.status(401).json({ error: "Username tidak ditemukan" });

  const user = rows[0];
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: "Password salah" });

  const token = jwt.sign(
    { id: user.id, role: user.role, nama: user.nama_lengkap },
    process.env.JWT_SECRET,
    { expiresIn: "7d" },
  );

  res.json({
    token,
    user: {
      id: user.id,
      nama: user.nama_lengkap,
      role: user.role,
      foto_profil: user.foto_profil,
    },
  });
});

router.get("/auth/me", verifyToken, async (req, res) => {
  const [rows] = await pool.query(
    "SELECT id,nama_lengkap,role,foto_profil FROM users WHERE id=?",
    [req.user.id],
  );
  res.json(rows[0]);
});

router.post("/register", async (req, res) => {
  const { nama_lengkap, nim, jurusan, no_hp, username, password } = req.body;

  const [cek] = await pool.query("SELECT id FROM users WHERE username=?", [
    username,
  ]);
  if (cek.length)
    return res.status(400).json({ error: "Username sudah dipakai" });

  const hashed = await bcrypt.hash(password, 10);
  const [result] = await pool.query(
    `INSERT INTO users (nama_lengkap,nim,jurusan,no_hp,username,password,role,status_laporan)
     VALUES (?,?,?,?,?,?,'peserta','locked')`,
    [nama_lengkap, nim, jurusan, no_hp, username, hashed],
  );

  res.json({ id: result.insertId });
});

// ==========================================================
// USERS (ADMIN ONLY)
// ==========================================================
router.get("/users/:role", verifyToken, allow("admin"), async (req, res) => {
  const [rows] = await pool.query(
    "SELECT id,nama_lengkap,nim,jurusan,role FROM users WHERE role=? ORDER BY id DESC",
    [req.params.role],
  );
  res.json(rows);
});

router.post("/users", verifyToken, allow("admin"), async (req, res) => {
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

router.put("/users/:id", verifyToken, allow("admin"), async (req, res) => {
  const id = req.params.id;
  const d = req.body;

  let q = `UPDATE users SET nama_lengkap=?,nim=?,jurusan=?,no_hp=?,username=?,role=?,company_id=?`;
  let v = [
    d.nama_lengkap,
    d.nim || null,
    d.jurusan || null,
    d.no_hp || null,
    d.username,
    d.role,
    d.company_id || null,
  ];

  if (d.password) {
    const hashed = await bcrypt.hash(d.password, 10);
    q += `,password=?`;
    v.push(hashed);
  }

  v.push(id);
  await pool.query(q + " WHERE id=?", v);
  res.json({ message: "updated" });
});

router.delete("/users/:id", verifyToken, allow("admin"), async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=?", [req.params.id]);
  res.json({ message: "deleted" });
});

// ==========================================================
// COMPANIES (ADMIN)
// ==========================================================
router.get(
  "/companies",
  verifyToken,
  allow("admin", "supervisor"),
  async (req, res) => {
    const [rows] = await pool.query("SELECT * FROM companies ORDER BY id DESC");
    res.json(rows);
  },
);

router.post("/companies", verifyToken, allow("admin"), async (req, res) => {
  const { nama_perusahaan, alamat, kontak } = req.body;
  await pool.query(
    "INSERT INTO companies (nama_perusahaan,alamat,kontak) VALUES (?,?,?)",
    [nama_perusahaan, alamat, kontak],
  );
  res.json({ message: "added" });
});

router.put("/companies/:id", verifyToken, allow("admin"), async (req, res) => {
  const { nama_perusahaan, alamat, kontak } = req.body;
  await pool.query(
    "UPDATE companies SET nama_perusahaan=?,alamat=?,kontak=? WHERE id=?",
    [nama_perusahaan, alamat, kontak, req.params.id],
  );
  res.json({ message: "updated" });
});

router.delete(
  "/companies/:id",
  verifyToken,
  allow("admin"),
  async (req, res) => {
    await pool.query("DELETE FROM companies WHERE id=?", [req.params.id]);
    res.json({ message: "deleted" });
  },
);

// ==========================================================
// PLACEMENTS
// ==========================================================
router.get(
  "/placements",
  verifyToken,
  allow("admin", "supervisor"),
  async (req, res) => {
    const [rows] = await pool.query(`
    SELECT p.id,u.nama_lengkap peserta,s.nama_lengkap supervisor,c.nama_perusahaan,
           p.user_id,p.supervisor_id,p.company_id
    FROM placements p
    JOIN users u ON p.user_id=u.id
    JOIN users s ON p.supervisor_id=s.id
    JOIN companies c ON p.company_id=c.id
    ORDER BY p.id DESC`);
    res.json(rows);
  },
);

router.post("/placements", verifyToken, allow("admin"), async (req, res) => {
  const { user_id, supervisor_id, company_id } = req.body;
  await pool.query(
    "INSERT INTO placements (user_id,supervisor_id,company_id) VALUES (?,?,?)",
    [user_id, supervisor_id, company_id],
  );
  res.json({ message: "added" });
});

router.put("/placements/:id", verifyToken, allow("admin"), async (req, res) => {
  const { user_id, supervisor_id, company_id } = req.body;
  await pool.query(
    "UPDATE placements SET user_id=?,supervisor_id=?,company_id=? WHERE id=?",
    [user_id, supervisor_id, company_id, req.params.id],
  );
  res.json({ message: "updated" });
});

router.delete(
  "/placements/:id",
  verifyToken,
  allow("admin"),
  async (req, res) => {
    await pool.query("DELETE FROM placements WHERE id=?", [req.params.id]);
    res.json({ message: "deleted" });
  },
);

// ==========================================================
// LOGBOOK
// ==========================================================
router.post(
  "/logbook",
  verifyToken,
  allow("peserta"),
  upload.single("bukti_foto"),
  async (req, res) => {
    const { kegiatan, tanggal } = req.body;
    const bukti = req.file ? req.file.filename : null;

    const [r] = await pool.query(
      "INSERT INTO logbooks (user_id,tanggal,kegiatan,bukti_foto,status) VALUES (?,?,?,?, 'menunggu')",
      [req.user.id, tanggal, kegiatan, bukti],
    );
    res.json({ id: r.insertId });
  },
);

router.get("/logbook/me", verifyToken, allow("peserta"), async (req, res) => {
  const [rows] = await pool.query(
    "SELECT * FROM logbooks WHERE user_id=? ORDER BY tanggal DESC",
    [req.user.id],
  );
  res.json(rows);
});

router.put(
  "/logbook-status/:id",
  verifyToken,
  allow("admin", "supervisor"),
  async (req, res) => {
    await pool.query("UPDATE logbooks SET status=? WHERE id=?", [
      req.body.status,
      req.params.id,
    ]);
    res.json({ message: "updated" });
  },
);

router.delete(
  "/logbook/:id",
  verifyToken,
  allow("admin", "peserta"),
  async (req, res) => {
    await pool.query("DELETE FROM logbooks WHERE id=?", [req.params.id]);
    res.json({ message: "deleted" });
  },
);

// ==========================================================
// ADMIN STATS
// ==========================================================
router.get("/admin/stats", verifyToken, allow("admin"), async (req, res) => {
  const [[peserta]] = await pool.query(
    "SELECT COUNT(*) c FROM users WHERE role='peserta'",
  );
  const [[supervisor]] = await pool.query(
    "SELECT COUNT(*) c FROM users WHERE role='supervisor'",
  );
  const [[logbooks]] = await pool.query("SELECT COUNT(*) c FROM logbooks");
  const [[companies]] = await pool.query("SELECT COUNT(*) c FROM companies");
  const [[placed]] = await pool.query("SELECT COUNT(*) c FROM placements");

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
