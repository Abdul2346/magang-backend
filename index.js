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

// ======================= CORS PRODUCTION =======================
const allowedOrigins = [
  process.env.CLIENT_URL,
  "https://magang.lpkcti.com",
  "http://magang.lpkcti.com",
  "http://localhost:5173",
  "http://localhost:3000",
].filter(Boolean); // Filter out undefined values

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps, curl, etc)
      if (!origin) return callback(null, true);

      if (allowedOrigins.indexOf(origin) === -1) {
        const msg =
          "The CORS policy for this site does not allow access from the specified Origin.";
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  }),
);

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// ==========================================================
// ROUTER PREFIX
// ==========================================================
const router = express.Router();
app.use("/api", router);

// ==========================================================
// DATABASE CONNECTION
// ==========================================================
const pool = mysql
  .createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0,
  })
  .promise();

// Test database connection
const testConnection = async () => {
  try {
    const connection = await pool.getConnection();
    console.log("✅ Database connected successfully to:", process.env.DB_NAME);
    console.log("📊 Database host:", process.env.DB_HOST);
    connection.release();
  } catch (error) {
    console.error("❌ Database connection failed:", error.message);
    console.error("🔧 Please check your database configuration");
  }
};

testConnection();

// ==========================================================
// UPLOAD DIRECTORY SETUP
// ==========================================================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log("📁 Uploads directory created:", uploadDir);
}

// Serve static files from uploads directory
app.use("/uploads", express.static(uploadDir));
router.use("/uploads", express.static(uploadDir));

// ==========================================================
// MULTER CONFIGURATION
// ==========================================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Sanitize filename
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname).toLowerCase();
    const fieldname = file.fieldname.replace(/[^a-z0-9]/gi, "_");
    cb(null, fieldname + "-" + uniqueSuffix + ext);
  },
});

const fileFilter = (req, file, cb) => {
  // Allowed file types
  const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx/;
  const extname = allowedTypes.test(
    path.extname(file.originalname).toLowerCase(),
  );
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(
      new Error(
        "File type not allowed. Only images, PDF, and DOC files are allowed.",
      ),
    );
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
});

// ==========================================================
// AUTH MIDDLEWARE
// ==========================================================
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;

  if (!auth) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized - No token provided",
    });
  }

  try {
    const token = auth.split(" ")[1];
    if (!token) {
      return res.status(401).json({
        success: false,
        error: "Unauthorized - Invalid token format",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(403).json({
        success: false,
        error: "Token expired",
      });
    }
    if (error.name === "JsonWebTokenError") {
      return res.status(403).json({
        success: false,
        error: "Invalid token",
      });
    }
    res.status(403).json({
      success: false,
      error: "Token verification failed",
    });
  }
};

const allow = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: "Unauthorized - User not authenticated",
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: "Akses ditolak - Anda tidak memiliki izin yang diperlukan",
      });
    }
    next();
  };
};

// ==========================================================
// AUTH ROUTES
// ==========================================================
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: "Username dan password harus diisi",
      });
    }

    const [rows] = await pool.query(
      "SELECT * FROM users WHERE username = ? AND deleted_at IS NULL",
      [username],
    );

    if (!rows.length) {
      return res.status(401).json({
        success: false,
        error: "Username tidak ditemukan",
      });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({
        success: false,
        error: "Password salah",
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
        nama: user.nama_lengkap,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    // Update last login
    await pool.query("UPDATE users SET last_login = NOW() WHERE id = ?", [
      user.id,
    ]);

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        nama: user.nama_lengkap,
        role: user.role,
        foto_profil: user.foto_profil,
        nim: user.nim,
        jurusan: user.jurusan,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

router.get("/auth/me", verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, nama_lengkap, nim, jurusan, no_hp, username, role, foto_profil, status_laporan, company_id, last_login, created_at FROM users WHERE id = ?",
      [req.user.id],
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        error: "User tidak ditemukan",
      });
    }

    res.json({
      success: true,
      user: rows[0],
    });
  } catch (error) {
    console.error("Auth me error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

router.post("/register", async (req, res) => {
  try {
    const { nama_lengkap, nim, jurusan, no_hp, username, password } = req.body;

    // Validasi input
    if (!nama_lengkap || !nim || !jurusan || !no_hp || !username || !password) {
      return res.status(400).json({
        success: false,
        error: "Semua field harus diisi",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Password minimal 6 karakter",
      });
    }

    // Cek username sudah dipakai
    const [cek] = await pool.query("SELECT id FROM users WHERE username = ?", [
      username,
    ]);

    if (cek.length) {
      return res.status(400).json({
        success: false,
        error: "Username sudah dipakai",
      });
    }

    const hashed = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      `INSERT INTO users
       (nama_lengkap, nim, jurusan, no_hp, username, password, role, status_laporan, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'peserta', 'locked', NOW())`,
      [nama_lengkap, nim, jurusan, no_hp, username, hashed],
    );

    res.json({
      success: true,
      message: "Registrasi berhasil",
      id: result.insertId,
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

// ==========================================================
// USERS (ADMIN ONLY)
// ==========================================================
router.get("/users/:role", verifyToken, allow("admin"), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, nama_lengkap, nim, jurusan, no_hp, username, role, foto_profil,
              status_laporan, company_id, last_login, created_at
       FROM users
       WHERE role = ? AND deleted_at IS NULL
       ORDER BY id DESC`,
      [req.params.role],
    );

    res.json({
      success: true,
      data: rows,
    });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

router.post("/users", verifyToken, allow("admin"), async (req, res) => {
  try {
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

    // Validasi
    if (!nama_lengkap || !username || !password || !role) {
      return res.status(400).json({
        success: false,
        error: "Data tidak lengkap",
      });
    }

    // Cek username
    const [cek] = await pool.query("SELECT id FROM users WHERE username = ?", [
      username,
    ]);

    if (cek.length) {
      return res.status(400).json({
        success: false,
        error: "Username sudah dipakai",
      });
    }

    const hashed = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      `INSERT INTO users
       (nama_lengkap, nim, jurusan, no_hp, username, password, role, status_laporan, company_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'locked', ?, NOW())`,
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

    res.json({
      success: true,
      message: "User berhasil ditambahkan",
      id: result.insertId,
    });
  } catch (error) {
    console.error("Create user error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

router.put("/users/:id", verifyToken, allow("admin"), async (req, res) => {
  try {
    const id = req.params.id;
    const d = req.body;

    let query = `UPDATE users SET
                 nama_lengkap = ?,
                 nim = ?,
                 jurusan = ?,
                 no_hp = ?,
                 username = ?,
                 role = ?,
                 company_id = ?,
                 updated_at = NOW()`;

    let values = [
      d.nama_lengkap,
      d.nim || null,
      d.jurusan || null,
      d.no_hp || null,
      d.username,
      d.role,
      d.company_id || null,
    ];

    if (d.password && d.password.trim() !== "") {
      const hashed = await bcrypt.hash(d.password, 10);
      query += `, password = ?`;
      values.push(hashed);
    }

    query += ` WHERE id = ?`;
    values.push(id);

    await pool.query(query, values);

    res.json({
      success: true,
      message: "User berhasil diupdate",
    });
  } catch (error) {
    console.error("Update user error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

router.delete("/users/:id", verifyToken, allow("admin"), async (req, res) => {
  try {
    // Soft delete
    await pool.query("UPDATE users SET deleted_at = NOW() WHERE id = ?", [
      req.params.id,
    ]);

    res.json({
      success: true,
      message: "User berhasil dihapus",
    });
  } catch (error) {
    console.error("Delete user error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

// ==========================================================
// COMPANIES (ADMIN & SUPERVISOR)
// ==========================================================
router.get(
  "/companies",
  verifyToken,
  allow("admin", "supervisor"),
  async (req, res) => {
    try {
      const [rows] = await pool.query(
        "SELECT * FROM companies WHERE deleted_at IS NULL ORDER BY id DESC",
      );

      res.json({
        success: true,
        data: rows,
      });
    } catch (error) {
      console.error("Get companies error:", error);
      res.status(500).json({
        success: false,
        error: "Terjadi kesalahan server",
      });
    }
  },
);

router.post("/companies", verifyToken, allow("admin"), async (req, res) => {
  try {
    const { nama_perusahaan, alamat, kontak } = req.body;

    if (!nama_perusahaan) {
      return res.status(400).json({
        success: false,
        error: "Nama perusahaan harus diisi",
      });
    }

    const [result] = await pool.query(
      "INSERT INTO companies (nama_perusahaan, alamat, kontak, created_at) VALUES (?, ?, ?, NOW())",
      [nama_perusahaan, alamat || null, kontak || null],
    );

    res.json({
      success: true,
      message: "Perusahaan berhasil ditambahkan",
      id: result.insertId,
    });
  } catch (error) {
    console.error("Create company error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

router.put("/companies/:id", verifyToken, allow("admin"), async (req, res) => {
  try {
    const { nama_perusahaan, alamat, kontak } = req.body;

    await pool.query(
      "UPDATE companies SET nama_perusahaan = ?, alamat = ?, kontak = ?, updated_at = NOW() WHERE id = ?",
      [nama_perusahaan, alamat || null, kontak || null, req.params.id],
    );

    res.json({
      success: true,
      message: "Perusahaan berhasil diupdate",
    });
  } catch (error) {
    console.error("Update company error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

router.delete(
  "/companies/:id",
  verifyToken,
  allow("admin"),
  async (req, res) => {
    try {
      // Soft delete
      await pool.query("UPDATE companies SET deleted_at = NOW() WHERE id = ?", [
        req.params.id,
      ]);

      res.json({
        success: true,
        message: "Perusahaan berhasil dihapus",
      });
    } catch (error) {
      console.error("Delete company error:", error);
      res.status(500).json({
        success: false,
        error: "Terjadi kesalahan server",
      });
    }
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
    try {
      const [rows] = await pool.query(`
      SELECT
        p.id,
        p.user_id,
        p.supervisor_id,
        p.company_id,
        u.nama_lengkap as peserta,
        u.nim as peserta_nim,
        u.jurusan as peserta_jurusan,
        s.nama_lengkap as supervisor,
        s.nim as supervisor_nim,
        c.nama_perusahaan,
        c.alamat as perusahaan_alamat,
        p.created_at,
        p.updated_at
      FROM placements p
      JOIN users u ON p.user_id = u.id AND u.deleted_at IS NULL
      JOIN users s ON p.supervisor_id = s.id AND s.deleted_at IS NULL
      JOIN companies c ON p.company_id = c.id AND c.deleted_at IS NULL
      WHERE p.deleted_at IS NULL
      ORDER BY p.id DESC
    `);

      res.json({
        success: true,
        data: rows,
      });
    } catch (error) {
      console.error("Get placements error:", error);
      res.status(500).json({
        success: false,
        error: "Terjadi kesalahan server",
      });
    }
  },
);

router.post("/placements", verifyToken, allow("admin"), async (req, res) => {
  try {
    const { user_id, supervisor_id, company_id } = req.body;

    // Validasi
    if (!user_id || !supervisor_id || !company_id) {
      return res.status(400).json({
        success: false,
        error: "Data tidak lengkap",
      });
    }

    // Cek apakah user sudah punya placement
    const [cek] = await pool.query(
      "SELECT id FROM placements WHERE user_id = ? AND deleted_at IS NULL",
      [user_id],
    );

    if (cek.length) {
      return res.status(400).json({
        success: false,
        error: "User sudah memiliki penempatan",
      });
    }

    const [result] = await pool.query(
      "INSERT INTO placements (user_id, supervisor_id, company_id, created_at) VALUES (?, ?, ?, NOW())",
      [user_id, supervisor_id, company_id],
    );

    // Update status_laporan user menjadi 'active'
    await pool.query(
      "UPDATE users SET status_laporan = 'active', company_id = ? WHERE id = ?",
      [company_id, user_id],
    );

    res.json({
      success: true,
      message: "Penempatan berhasil ditambahkan",
      id: result.insertId,
    });
  } catch (error) {
    console.error("Create placement error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

router.put("/placements/:id", verifyToken, allow("admin"), async (req, res) => {
  try {
    const { user_id, supervisor_id, company_id } = req.body;

    await pool.query(
      "UPDATE placements SET user_id = ?, supervisor_id = ?, company_id = ?, updated_at = NOW() WHERE id = ?",
      [user_id, supervisor_id, company_id, req.params.id],
    );

    // Update company_id di users
    await pool.query("UPDATE users SET company_id = ? WHERE id = ?", [
      company_id,
      user_id,
    ]);

    res.json({
      success: true,
      message: "Penempatan berhasil diupdate",
    });
  } catch (error) {
    console.error("Update placement error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

router.delete(
  "/placements/:id",
  verifyToken,
  allow("admin"),
  async (req, res) => {
    try {
      // Get placement data first
      const [placement] = await pool.query(
        "SELECT user_id FROM placements WHERE id = ?",
        [req.params.id],
      );

      if (placement.length) {
        // Reset user status
        await pool.query(
          "UPDATE users SET status_laporan = 'locked', company_id = NULL WHERE id = ?",
          [placement[0].user_id],
        );
      }

      // Soft delete placement
      await pool.query(
        "UPDATE placements SET deleted_at = NOW() WHERE id = ?",
        [req.params.id],
      );

      res.json({
        success: true,
        message: "Penempatan berhasil dihapus",
      });
    } catch (error) {
      console.error("Delete placement error:", error);
      res.status(500).json({
        success: false,
        error: "Terjadi kesalahan server",
      });
    }
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
    try {
      const { kegiatan, tanggal } = req.body;
      const bukti = req.file ? req.file.filename : null;

      if (!kegiatan || !tanggal) {
        return res.status(400).json({
          success: false,
          error: "Kegiatan dan tanggal harus diisi",
        });
      }

      const [result] = await pool.query(
        `INSERT INTO logbooks
       (user_id, tanggal, kegiatan, bukti_foto, status, created_at)
       VALUES (?, ?, ?, ?, 'menunggu', NOW())`,
        [req.user.id, tanggal, kegiatan, bukti],
      );

      res.json({
        success: true,
        message: "Logbook berhasil ditambahkan",
        id: result.insertId,
      });
    } catch (error) {
      console.error("Create logbook error:", error);
      res.status(500).json({
        success: false,
        error: "Terjadi kesalahan server",
      });
    }
  },
);

router.get("/logbook/me", verifyToken, allow("peserta"), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM logbooks
       WHERE user_id = ? AND deleted_at IS NULL
       ORDER BY tanggal DESC, created_at DESC`,
      [req.user.id],
    );

    // Add URL for photos
    const baseUrl = `${req.protocol}://${req.get("host")}`;
    const data = rows.map((row) => ({
      ...row,
      bukti_foto_url: row.bukti_foto ? `/api/uploads/${row.bukti_foto}` : null,
    }));

    res.json({
      success: true,
      data: data,
    });
  } catch (error) {
    console.error("Get my logbook error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

router.get(
  "/logbook/supervisor",
  verifyToken,
  allow("supervisor"),
  async (req, res) => {
    try {
      // Get all participants under this supervisor
      const [rows] = await pool.query(
        `
      SELECT
        l.*,
        u.nama_lengkap as peserta_nama,
        u.nim as peserta_nim,
        u.jurusan as peserta_jurusan,
        c.nama_perusahaan
      FROM logbooks l
      JOIN users u ON l.user_id = u.id AND u.deleted_at IS NULL
      JOIN placements p ON u.id = p.user_id AND p.deleted_at IS NULL
      JOIN companies c ON p.company_id = c.id AND c.deleted_at IS NULL
      WHERE p.supervisor_id = ? AND l.deleted_at IS NULL
      ORDER BY l.tanggal DESC, l.created_at DESC
    `,
        [req.user.id],
      );

      // Add URL for photos
      const baseUrl = `${req.protocol}://${req.get("host")}`;
      const data = rows.map((row) => ({
        ...row,
        bukti_foto_url: row.bukti_foto
          ? `/api/uploads/${row.bukti_foto}`
          : null,
      }));

      res.json({
        success: true,
        data: data,
      });
    } catch (error) {
      console.error("Get supervisor logbook error:", error);
      res.status(500).json({
        success: false,
        error: "Terjadi kesalahan server",
      });
    }
  },
);

router.put(
  "/logbook-status/:id",
  verifyToken,
  allow("admin", "supervisor"),
  async (req, res) => {
    try {
      const { status } = req.body;
      const { id } = req.params;

      if (!["disetujui", "ditolak", "menunggu"].includes(status)) {
        return res.status(400).json({
          success: false,
          error: "Status tidak valid",
        });
      }

      await pool.query(
        "UPDATE logbooks SET status = ?, updated_at = NOW() WHERE id = ?",
        [status, id],
      );

      res.json({
        success: true,
        message: `Logbook berhasil ${status === "disetujui" ? "disetujui" : status === "ditolak" ? "ditolak" : "diupdate"}`,
      });
    } catch (error) {
      console.error("Update logbook status error:", error);
      res.status(500).json({
        success: false,
        error: "Terjadi kesalahan server",
      });
    }
  },
);

router.delete(
  "/logbook/:id",
  verifyToken,
  allow("admin", "peserta"),
  async (req, res) => {
    try {
      // If user is participant, check if they own this logbook
      if (req.user.role === "peserta") {
        const [logbook] = await pool.query(
          "SELECT id FROM logbooks WHERE id = ? AND user_id = ?",
          [req.params.id, req.user.id],
        );

        if (!logbook.length) {
          return res.status(403).json({
            success: false,
            error: "Anda tidak memiliki izin untuk menghapus logbook ini",
          });
        }
      }

      // Soft delete
      await pool.query("UPDATE logbooks SET deleted_at = NOW() WHERE id = ?", [
        req.params.id,
      ]);

      res.json({
        success: true,
        message: "Logbook berhasil dihapus",
      });
    } catch (error) {
      console.error("Delete logbook error:", error);
      res.status(500).json({
        success: false,
        error: "Terjadi kesalahan server",
      });
    }
  },
);

// ==========================================================
// ADMIN STATS
// ==========================================================
router.get("/admin/stats", verifyToken, allow("admin"), async (req, res) => {
  try {
    const [[peserta]] = await pool.query(
      "SELECT COUNT(*) as total FROM users WHERE role = 'peserta' AND deleted_at IS NULL",
    );

    const [[supervisor]] = await pool.query(
      "SELECT COUNT(*) as total FROM users WHERE role = 'supervisor' AND deleted_at IS NULL",
    );

    const [[logbooks]] = await pool.query(
      "SELECT COUNT(*) as total FROM logbooks WHERE deleted_at IS NULL",
    );

    const [[companies]] = await pool.query(
      "SELECT COUNT(*) as total FROM companies WHERE deleted_at IS NULL",
    );

    const [[placed]] = await pool.query(
      "SELECT COUNT(*) as total FROM placements WHERE deleted_at IS NULL",
    );

    const [[logbooksToday]] = await pool.query(
      "SELECT COUNT(*) as total FROM logbooks WHERE DATE(created_at) = CURDATE() AND deleted_at IS NULL",
    );

    const [[pendingLogbooks]] = await pool.query(
      "SELECT COUNT(*) as total FROM logbooks WHERE status = 'menunggu' AND deleted_at IS NULL",
    );

    res.json({
      success: true,
      data: {
        total_peserta: peserta.total,
        total_supervisor: supervisor.total,
        total_logbooks: logbooks.total,
        total_perusahaan: companies.total,
        total_placed: placed.total,
        logbooks_hari_ini: logbooksToday.total,
        logbooks_pending: pendingLogbooks.total,
      },
    });
  } catch (error) {
    console.error("Get admin stats error:", error);
    res.status(500).json({
      success: false,
      error: "Terjadi kesalahan server",
    });
  }
});

// ==========================================================
// SUPERVISOR STATS
// ==========================================================
router.get(
  "/supervisor/stats",
  verifyToken,
  allow("supervisor"),
  async (req, res) => {
    try {
      // Get participants under this supervisor
      const [[participants]] = await pool.query(
        `SELECT COUNT(DISTINCT p.user_id) as total
       FROM placements p
       WHERE p.supervisor_id = ? AND p.deleted_at IS NULL`,
        [req.user.id],
      );

      // Get logbooks from their participants
      const [[logbooks]] = await pool.query(
        `SELECT COUNT(*) as total
       FROM logbooks l
       JOIN placements p ON l.user_id = p.user_id
       WHERE p.supervisor_id = ? AND l.deleted_at IS NULL`,
        [req.user.id],
      );

      // Get pending approvals
      const [[pending]] = await pool.query(
        `SELECT COUNT(*) as total
       FROM logbooks l
       JOIN placements p ON l.user_id = p.user_id
       WHERE p.supervisor_id = ? AND l.status = 'menunggu' AND l.deleted_at IS NULL`,
        [req.user.id],
      );

      res.json({
        success: true,
        data: {
          total_peserta: participants.total,
          total_logbooks: logbooks.total,
          perlu_disetujui: pending.total,
        },
      });
    } catch (error) {
      console.error("Get supervisor stats error:", error);
      res.status(500).json({
        success: false,
        error: "Terjadi kesalahan server",
      });
    }
  },
);

// ==========================================================
// PARTICIPANT STATS
// ==========================================================
router.get(
  "/participant/stats",
  verifyToken,
  allow("peserta"),
  async (req, res) => {
    try {
      const [[logbooks]] = await pool.query(
        "SELECT COUNT(*) as total FROM logbooks WHERE user_id = ? AND deleted_at IS NULL",
        [req.user.id],
      );

      const [[approved]] = await pool.query(
        "SELECT COUNT(*) as total FROM logbooks WHERE user_id = ? AND status = 'disetujui' AND deleted_at IS NULL",
        [req.user.id],
      );

      const [[pending]] = await pool.query(
        "SELECT COUNT(*) as total FROM logbooks WHERE user_id = ? AND status = 'menunggu' AND deleted_at IS NULL",
        [req.user.id],
      );

      const [[rejected]] = await pool.query(
        "SELECT COUNT(*) as total FROM logbooks WHERE user_id = ? AND status = 'ditolak' AND deleted_at IS NULL",
        [req.user.id],
      );

      // Get participant's company
      const [[placement]] = await pool.query(
        `SELECT c.nama_perusahaan, c.alamat
       FROM placements p
       JOIN companies c ON p.company_id = c.id
       WHERE p.user_id = ? AND p.deleted_at IS NULL`,
        [req.user.id],
      );

      res.json({
        success: true,
        data: {
          total_logbooks: logbooks.total,
          logbooks_disetujui: approved.total,
          logbooks_pending: pending.total,
          logbooks_ditolak: rejected.total,
          perusahaan: placement || null,
        },
      });
    } catch (error) {
      console.error("Get participant stats error:", error);
      res.status(500).json({
        success: false,
        error: "Terjadi kesalahan server",
      });
    }
  },
);

// ==========================================================
// HEALTH CHECK & ERROR HANDLING
// ==========================================================
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "API MAGANG RUNNING 🚀",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    version: "1.0.0",
  });
});

app.get("/health", async (req, res) => {
  try {
    // Check database
    const [dbCheck] = await pool.query("SELECT 1 as health");

    res.json({
      success: true,
      status: "healthy",
      database: dbCheck ? "connected" : "disconnected",
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      status: "unhealthy",
      database: "disconnected",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint tidak ditemukan",
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Global error:", err);

  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        success: false,
        error: "File terlalu besar. Maksimal 5MB",
      });
    }
    return res.status(400).json({
      success: false,
      error: err.message,
    });
  }

  if (err.message.includes("File type not allowed")) {
    return res.status(400).json({
      success: false,
      error: err.message,
    });
  }

  res.status(500).json({
    success: false,
    error: "Terjadi kesalahan internal server",
  });
});

// ==========================================================
// START SERVER
// ==========================================================
const PORT = process.env.PORT || 8080;
const HOST = "0.0.0.0";

const server = app.listen(PORT, HOST, () => {
  console.log(`
╔════════════════════════════════════════════╗
║     🚀 SERVER MAGANG BERHASIL JALAN       ║
╠════════════════════════════════════════════╣
║  Port: ${PORT}
║  Host: ${HOST}
║  URL: https://magang-backend-production.up.railway.app
║  Environment: ${process.env.NODE_ENV || "development"}
║  CORS Allowed: ${allowedOrigins.join(", ")}
╚════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM signal received: closing HTTP server");
  server.close(() => {
    console.log("HTTP server closed");
    pool.end();
  });
});

process.on("SIGINT", () => {
  console.log("SIGINT signal received: closing HTTP server");
  server.close(() => {
    console.log("HTTP server closed");
    pool.end();
  });
});

module.exports = app;
