import dotenv from "dotenv";
import express from "express";
import path from "path";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import fs from "fs";
import pg from "pg";
import { fileURLToPath } from "url";

dotenv.config();

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

pool.query("SELECT NOW()", (err, result) => {
  if (err) {
    console.error("❌ Lỗi kết nối database:", err.message);
  } else {
    console.log("✅ Kết nối Neon database thành công!");
  }
});

const app = express();
app.use(cors({
  origin: "http://localhost:5500",
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"],
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const UPLOAD_DIR = path.join(__dirname, "..", "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const name = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}${ext}`;
    cb(null, name);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Chỉ chấp nhận file ảnh"));
    }
    cb(null, true);
  },
});

app.use(express.static(path.join(__dirname, "../public")));
app.use("/admin", express.static(path.join(__dirname, "../admin/public")));
app.use("/uploads", express.static(UPLOAD_DIR));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/home.html"));
});

app.get("/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ status: "ok", time: result.rows[0].now });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

function authorize(allowedRoles) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET || "defaultsecret");
      if (!allowedRoles.includes(payload.role)) {
        return res.status(403).json({ error: "Forbidden" });
      }
      req.user = payload;
      next();
    } catch {
      res.status(401).json({ error: "Invalid token" });
    }
  };
}

app.post("/auth/register", async (req, res) => {
  const { fullName, username, email, phone, password, role } = req.body;
  if (!fullName || !username || !email || !phone || !password) {
    return res.status(400).json({ error: "Thiếu thông tin đăng ký" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO users (username, email, password_hash, full_name, phone, role, is_active)
       VALUES ($1,$2,$3,$4,$5, $6, true)`,
      [username, email, hashedPassword, fullName, phone, role || "guest"]
    );
    res.status(201).json({ message: "Đăng ký thành công" });
  } catch (err) {
    if (err.code === "23505") {
      res.status(400).json({ error: "Email hoặc Username đã tồn tại" });
    } else {
      console.error("❌ Lỗi đăng ký:", err);
      res.status(500).json({ error: "Lỗi server khi đăng ký" });
    }
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query(
      "SELECT id, email, username, password_hash, role, full_name, phone FROM users WHERE email=$1 AND is_active=true",
      [email]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: "Tài khoản không tồn tại hoặc bị khóa" });
    }
    const user = rows[0];
    const validPassword = user.password_hash.startsWith("$2b$")
      ? await bcrypt.compare(password, user.password_hash)
      : password === user.password_hash;
    if (!validPassword) {
      return res.status(401).json({ error: "Sai mật khẩu" });
    }
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET || "defaultsecret",
      { expiresIn: "8h" }
    );
    res.json({
      message: "Đăng nhập thành công",
      token,
      id: user.id,
      username: user.username,
      full_name: user.full_name,
      role: user.role,
      phone: user.phone,
      email: user.email
    });
  } catch (err) {
    console.error("❌ Lỗi đăng nhập:", err);
    res.status(500).json({ error: "Lỗi server khi đăng nhập" });
  }
});

// API 1: Tổng số booking
app.get("/api/bookings/total", async (req, res) => {
  try {
    const r = await pool.query("SELECT COUNT(*) AS total FROM bookings");
    res.json({ total: Number(r.rows[0].total) });
  } catch (err) {
    console.error("❌ Lỗi khi lấy tổng booking:", err);
    res.status(500).json({ error: "Lỗi server" });
  }
});

// API 2: Tổng doanh thu toàn hệ thống
app.get("/api/revenue/total", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT COALESCE(SUM(total_amount), 0)::BIGINT AS total_revenue
      FROM bookings
      WHERE status = 'confirmed';
    `);
    console.log("🟢 API /api/revenue/total:", result.rows[0]);
    res.json({ total_revenue: Number(result.rows[0].total_revenue) });
  } catch (err) {
    console.error("❌ Lỗi khi tính tổng doanh thu:", err);
    res.status(500).json({ error: "Lỗi khi tính tổng doanh thu" });
  }
});

// API 3: Doanh thu tháng hiện tại
app.get("/api/revenue/current-month", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT COALESCE(SUM(total_amount), 0)::BIGINT AS monthly_revenue
      FROM bookings
      WHERE status = 'confirmed'
        AND EXTRACT(MONTH FROM check_in) = EXTRACT(MONTH FROM CURRENT_DATE)
        AND EXTRACT(YEAR FROM check_in) = EXTRACT(YEAR FROM CURRENT_DATE);
    `);
    console.log("🟠 API /api/revenue/current-month:", rows[0]);
    res.json({ monthly_revenue: Number(rows[0].monthly_revenue) });
  } catch (err) {
    console.error("❌ Lỗi khi lấy doanh thu tháng hiện tại:", err);
    res.status(500).json({ error: "Lỗi server khi lấy doanh thu tháng hiện tại" });
  }
});

// API 4: Số khách mới trong 30 ngày gần nhất
app.get("/api/guests/new", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT COUNT(*) AS new_guests
      FROM users
      WHERE created_at >= NOW() - INTERVAL '30 days';
    `);
    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ Error loading new guests:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// API 5: Xu hướng doanh thu theo tháng
app.get("/api/revenue/monthly", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        TO_CHAR(DATE_TRUNC('month', check_in), 'YYYY-MM') AS month,
        COALESCE(SUM(total_amount), 0) AS total_revenue
      FROM bookings
      WHERE status = 'confirmed'
      GROUP BY 1
      ORDER BY 1;
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Lỗi khi lấy doanh thu theo tháng:", err);
    res.status(500).json({ error: "Lỗi server khi truy vấn doanh thu theo tháng" });
  }
});

app.get("/api/admin/customers", authorize(["admin", "staff"]), async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, username, full_name, email, created_at FROM users WHERE role='guest' ORDER BY created_at DESC"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Lỗi server" });
  }
});

app.get("/api/admin/customers/:id", authorize(["admin", "staff"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      "SELECT id, username, full_name, email, phone, created_at FROM users WHERE id=$1 AND role='guest'",
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Không tìm thấy" });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Lỗi server" });
  }
});

// ===== API QUẢN LÝ RESORTS =====
app.get("/api/admin/resorts", authorize(['admin', 'staff']), async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM resorts ORDER BY name ASC");
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: "Lỗi server khi lấy danh sách resort" });
  }
});

app.post("/api/admin/resorts", authorize(['admin', 'staff']), async (req, res) => {
  const { name } = req.body;
  if (!name || name.trim() === '') {
    return res.status(400).json({ error: "Tên resort là bắt buộc" });
  }
  try {
    const { rows } = await pool.query(
      "INSERT INTO resorts (name) VALUES ($1) RETURNING *",
      [name.trim()]
    );
    res.status(201).json(rows[0]);
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: "Tên resort này đã tồn tại." });
    }
    res.status(500).json({ error: "Lỗi server khi tạo resort" });
  }
});

// ===== API QUẢN LÝ PHÒNG =====
app.get("/api/rooms", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT r.id, res.name AS resort_name, r.location, r.category, r.address,
               rt.name AS room_type, rt.capacity,
               rd.description,
               rd.features,
               COALESCE(rd.images_url, '[]'::text) AS images_url,
               rd.price_per_night,
               rd.num_bed
       FROM rooms r 
       JOIN room_types rt ON r.room_type_id = rt.id
       JOIN resorts res ON r.resort_id = res.id
       LEFT JOIN room_details rd ON rd.room_id = r.id`
    );
    
    // ✅ Convert images - FIX CHO COMMA-SEPARATED
    const processedRooms = rows.map(room => {
      let images = [];
      
      if (room.images_url) {
        try {
          const parsed = JSON.parse(room.images_url);
          
          if (Array.isArray(parsed)) {
            images = parsed.map(item => {
              if (typeof item === 'string') {
                let cleaned = item.replace(/[{}]/g, '').replace(/"/g, '');
                if (cleaned.includes(',')) {
                  return cleaned.split(',').map(img => img.trim());
                }
                return cleaned;
              }
              return item;
            }).flat().filter(img => img && img.trim() !== '');
          } else if (typeof parsed === 'string') {
            let cleaned = parsed.replace(/[{}]/g, '').replace(/"/g, '');
            if (cleaned.includes(',')) {
              images = cleaned.split(',').map(img => img.trim()).filter(img => img);
            } else {
              images = [cleaned];
            }
          }
        } catch (e) {
          // Không phải JSON
          if (typeof room.images_url === 'string' && room.images_url.trim()) {
            let cleaned = room.images_url.replace(/[{}]/g, '').replace(/"/g, '');
            if (cleaned.includes(',')) {
              images = cleaned.split(',').map(img => img.trim()).filter(img => img);
            } else {
              images = [cleaned];
            }
          }
        }
      }
      
      room.images = images;
      delete room.images_url;
      return room;
    });
    
    res.json(processedRooms);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

app.get("/api/rooms/top-booked", async (req, res) => {
  try {
    const { limit = 5 } = req.query;
    const result = await pool.query(
      `SELECT r.id, r.category, r.location, COUNT(b.id) AS booking_count,
              COALESCE(SUM(b.total_amount), 0)::BIGINT AS total_revenue
       FROM rooms r LEFT JOIN bookings b ON b.room_id = r.id AND b.status = 'confirmed'
       GROUP BY r.id, r.category, r.location ORDER BY booking_count DESC LIMIT $1`,
      [limit]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Lỗi:", err);
    res.status(500).json({ error: "Lỗi server" });
  }
});

app.get("/api/rooms/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      `SELECT r.id, res.name AS resort_name, r.location, r.category, r.address,
               rt.name AS room_type, rt.capacity, 
               COALESCE(rd.description, 'Chưa có mô tả') AS description,
               COALESCE(rd.features, '{}'::text[]) AS features,
               COALESCE(rd.images_url, '[]'::text) AS images_url,
               rd.price_per_night,
               rd.num_bed
       FROM rooms r 
       JOIN room_types rt ON r.room_type_id = rt.id
       JOIN resorts res ON r.resort_id = res.id
       LEFT JOIN room_details rd ON rd.room_id = r.id 
       WHERE r.id = $1 LIMIT 1`,
      [id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ error: "Không tìm thấy phòng" });
    }
    
    // ✅ Convert images - FIX CHO COMMA-SEPARATED
    const room = rows;
    let images = [];
    
    if (room.images_url) {
      try {
        const parsed = JSON.parse(room.images_url);
        
        if (Array.isArray(parsed)) {
          images = parsed.map(item => {
            if (typeof item === 'string') {
              let cleaned = item.replace(/[{}]/g, '').replace(/"/g, '');
              if (cleaned.includes(',')) {
                return cleaned.split(',').map(img => img.trim());
              }
              return cleaned;
            }
            return item;
          }).flat().filter(img => img && img.trim() !== '');
        } else if (typeof parsed === 'string') {
          let cleaned = parsed.replace(/[{}]/g, '').replace(/"/g, '');
          if (cleaned.includes(',')) {
            images = cleaned.split(',').map(img => img.trim()).filter(img => img);
          } else {
            images = [cleaned];
          }
        }
      } catch (e) {
        if (typeof room.images_url === 'string' && room.images_url.trim()) {
          let cleaned = room.images_url.replace(/[{}]/g, '').replace(/"/g, '');
          if (cleaned.includes(',')) {
            images = cleaned.split(',').map(img => img.trim()).filter(img => img);
          } else {
            images = [cleaned];
          }
        }
      }
    }
    
    room.images = images;
    delete room.images_url;
    
    res.json(room);
  } catch (error) {
    console.error("❌ Lỗi:", error);
    res.status(500).json({ error: "Lỗi server" });
  }
});




app.post("/api/reviews", async (req, res) => {
  try {
    const { room_id, rating, comment, username } = req.body;
    if (!room_id || !rating || !comment || !username) {
      return res.status(400).json({ error: "Thiếu thông tin bắt buộc" });
    }
    const { rows } = await pool.query(
      `INSERT INTO reviews (room_id, rating, comment, username) VALUES ($1, $2, $3, $4)
       RETURNING review_id, created_at`,
      [room_id, rating, comment, username]
    );
    res.status(201).json({
      message: "Đánh giá đã được gửi thành công!",
      review_id: rows[0].review_id,
      created_at: rows[0].created_at,
    });
  } catch (error) {
    console.error("❌ Lỗi:", error);
    res.status(500).json({ error: "Lỗi server" });
  }
});

app.get("/api/reviews/:roomId", async (req, res) => {
  try {
    const { roomId } = req.params;
    const { rows } = await pool.query(
      `SELECT review_id, room_id, rating, comment, username, created_at FROM reviews
       WHERE room_id = $1 ORDER BY created_at DESC`,
      [roomId]
    );
    res.json(rows);
  } catch (error) {
    console.error("❌ Lỗi:", error);
    res.status(500).json({ error: "Lỗi server" });
  }
});

app.get("/api/admin/room-types", authorize(["admin", "staff"]), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, capacity FROM room_types WHERE is_active = true ORDER BY name"
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Lỗi server" });
  }
});

app.get("/api/room-types", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT DISTINCT name FROM room_types WHERE is_active = true ORDER BY name"
    );
    const types = result.rows.map((r) => r.name);
    res.json(types);
  } catch (error) {
    res.status(500).json({ error: "Lỗi server" });
  }
});

// ✅ GET danh sách phòng admin (với room_type_id)
app.get("/api/admin/rooms", authorize(["admin", "staff"]), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
          r.id, 
          res.name as resort_name,
          r.resort_id,
          r.room_type_id,
          rt.name AS room_type, 
          rd.price_per_night,
          rd.description, 
          rd.features, 
          rd.images_url AS images,
          r.status, 
          r.category, 
          r.location, 
          r.address, 
          rd.num_bed
       FROM rooms r 
       JOIN room_types rt ON r.room_type_id = rt.id
       JOIN resorts res ON r.resort_id = res.id
       LEFT JOIN room_details rd ON rd.room_id = r.id 
       ORDER BY res.name, r.created_at DESC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Lỗi khi lấy danh sách phòng admin:", error);
    res.status(500).json({ error: "Lỗi server" });
  }
});

app.get("/api/admin/rooms/:id", authorize(["admin", "staff"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      `SELECT r.id, r.resort_id, r.room_type_id, rt.name AS room_type,
              r.status, r.category, r.location, r.address, rd.description, rd.features,
// [!code-word:price_per_night]
              rd.images_url AS images, rd.num_bed, rd.price_per_night
       FROM rooms r JOIN room_types rt ON r.room_type_id = rt.id
       LEFT JOIN room_details rd ON rd.room_id = r.id WHERE r.id = $1`,
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Không tìm thấy phòng" });
    res.json(rows[0]);
  } catch (err) {
    console.error("❌ Lỗi:", err);
    res.status(500).json({ error: "Lỗi server" });
  }
});

// ✅ POST tạo phòng mới (LƯU GIÁ VÀO room_details)
app.post("/api/admin/rooms", authorize(["admin", "staff"]), upload.array('images'), async (req, res) => {
  try {
    const { resort_id, room_type_id, status, category, location, address, description, num_bed, price_per_night } = req.body;

    if (!resort_id || !room_type_id) {
      return res.status(400).json({ error: "Thiếu thông tin Resort ID hoặc Loại phòng" });
    }
    
    const imageNames = (req.files && req.files.length > 0) ? req.files.map(f => f.filename) : [];
    const client = await pool.connect();
    
    try {
      await client.query("BEGIN");
      
      const roomResult = await client.query(
        `INSERT INTO rooms (resort_id, room_type_id, status, category, location, address, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id`,
        [resort_id, room_type_id, status || "available", category || "standard", location, address || ""]
      );
      const roomId = roomResult.rows[0].id;

      // ✅ LƯU GIÁ VÀO room_details
      await client.query(
        `INSERT INTO room_details (room_id, description, features, images_url, num_bed, price_per_night, created_at) 
         VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
        [roomId, description || "", [], imageNames, num_bed || '', parseFloat(price_per_night) || 0]
      );

      await client.query("COMMIT");
      res.status(201).json({ message: "Thêm phòng thành công" });
    } catch (dbErr) {
      await client.query("ROLLBACK");
      throw dbErr;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("❌ POST Error:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

// ✅ PUT cập nhật phòng (LƯU GIÁ VÀO room_details)
app.put("/api/admin/rooms/:id", authorize(["admin", "staff"]), upload.array('images'), async (req, res) => {
  try {
    const { id } = req.params;
    const { resort_id, room_type_id, status, category, location, address, description, num_bed, price_per_night } = req.body;
    
    const imageNames = (req.files && req.files.length > 0) ? req.files.map(f => f.filename) : [];
    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const updateResult = await client.query(
        `UPDATE rooms SET 
            resort_id=$1, room_type_id=$2, status=$3, category=$4, 
            location=$5, address=$6, updated_at=NOW()
         WHERE id=$7 RETURNING id`,
        [resort_id, room_type_id, status, category, location, address, id]
      );

      if (updateResult.rowCount === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Không tìm thấy phòng" });
      }

      const existingDetail = await client.query("SELECT id FROM room_details WHERE room_id=$1", [id]);
      
      if (existingDetail.rows.length > 0) {
        // ✅ CẬP NHẬT room_details (LƯU GIÁ)
        let updateQuery = 'UPDATE room_details SET description = $1, num_bed = $2, price_per_night = $3, updated_at = NOW()';
        const params = [description || '', num_bed || '', parseFloat(price_per_night) || 0];
        
        if (imageNames.length > 0) {
          params.push(imageNames);
          updateQuery += `, images_url = $${params.length}`;
        }
        params.push(id);
        updateQuery += ` WHERE room_id = $${params.length}`;
        await client.query(updateQuery, params);
      } else {
        // ✅ THÊM room_details MỚI (LƯU GIÁ)
        await client.query(
          `INSERT INTO room_details (room_id, description, features, images_url, num_bed, price_per_night, created_at) 
           VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
          [id, description || "", [], imageNames, num_bed || '', parseFloat(price_per_night) || 0]
        );
      }

      await client.query("COMMIT");
      res.json({ message: "Cập nhật phòng thành công" });
    } catch (dbErr) {
      await client.query("ROLLBACK");
      throw dbErr;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("❌ PUT Error:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

// ===== API XÓA PHÒNG =====
app.delete("/api/admin/rooms/:id", authorize(['admin', 'staff']), async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect(); 

  try {
    await client.query('BEGIN');

    const bookingCheck = await client.query(
      'SELECT id FROM bookings WHERE room_id = $1 LIMIT 1', 
      [id]
    );

    if (bookingCheck.rowCount > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ 
        error: "Không thể xóa phòng này vì đã có khách đặt. Hãy xem xét chuyển trạng thái phòng sang bảo trì." 
      });
    }

    const deleteResult = await client.query(
      'DELETE FROM rooms WHERE id = $1 RETURNING id', 
      [id]
    );

    if (deleteResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: "Không tìm thấy phòng để xóa." });
    }

    await client.query('COMMIT');
    res.status(200).json({ 
      message: "Xóa phòng thành công!", 
      deletedRoomId: deleteResult.rows[0].id 
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Lỗi khi xóa phòng:", error);
    res.status(500).json({ error: "Lỗi server khi xóa phòng." });
  } finally {
    client.release(); 
  }
});

// ===== BOOKING API =====
app.post("/api/bookings", authorize(['guest', 'staff', 'admin']), async (req, res) => {
  const { userId } = req.user;
  const { roomId, checkIn, checkOut, pricePerNight } = req.body;

  if (!userId || !roomId || !checkIn || !checkOut || !pricePerNight) {
    return res.status(400).json({ error: "Thiếu thông tin đặt phòng." });
  }

  try {
    const parseDate = (str) => { const [day, month, year] = str.split('/'); return `${year}-${month}-${day}`; };
    const startDate = new Date(parseDate(checkIn));
    const endDate = new Date(parseDate(checkOut));
    const timeDiff = endDate.getTime() - startDate.getTime();
    const nights = Math.max(1, Math.ceil(timeDiff / (1000 * 3600 * 24)));
    const totalAmount = nights * pricePerNight;

    const sql = `
      INSERT INTO bookings (user_id, room_id, check_in, check_out, nightly_rate, total_amount, status)
      VALUES ($1, $2, $3, $4, $5, $6, 'pending')
      RETURNING id, booking_code, total_amount;
    `;
    
    const params = [userId, roomId, parseDate(checkIn), parseDate(checkOut), pricePerNight, totalAmount];
    
    const { rows } = await pool.query(sql, params);
    res.status(201).json({
      message: "Đặt phòng thành công!",
      booking: rows[0]
    });

  } catch (error) {
    console.error("❌ Lỗi khi tạo booking:", error);
    res.status(500).json({ error: "Lỗi server khi tạo đơn đặt phòng." });
  }
});

// =============================================================
// ===== 1. API LẤY LỊCH SỬ ĐẶT PHÒNG USER (ĐÃ NÂNG CẤP XỬ LÝ ẢNH) =====
// =============================================================
app.get("/api/my-bookings", authorize(['guest']), async (req, res) => {
  const { userId } = req.user;
  try {
    const sql = `
      SELECT 
        b.id, b.booking_code, b.check_in, b.check_out, b.total_amount, b.status, b.created_at,
        COALESCE(res.name, 'Resort không tồn tại') AS resort_name,
        rd.images_url -- Lấy nguyên gốc để xử lý kỹ
      FROM bookings b
      LEFT JOIN rooms r ON b.room_id = r.id
      LEFT JOIN resorts res ON r.resort_id = res.id
      LEFT JOIN room_details rd ON r.id = rd.room_id
      WHERE b.user_id = $1
      ORDER BY b.created_at DESC`;
      
    const { rows } = await pool.query(sql, [userId]);

    const processed = rows.map(item => {
        let imgs = [];
        const raw = item.images_url;

        if (raw) {
            try {
                // Cách 1: Thử Parse JSON chuẩn (ví dụ: '["a.jpg", "b.jpg"]')
                const parsed = JSON.parse(raw);
                if (Array.isArray(parsed)) imgs = parsed;
                else if (typeof parsed === 'string') imgs = [parsed];
            } catch (e) {
                // Cách 2: Nếu lỗi JSON, thử xử lý chuỗi Postgres (ví dụ: '{a.jpg,b.jpg}')
                if (typeof raw === 'string') {
                    // Xóa sạch các ký tự ngoặc nhọn, ngoặc vuông, nháy kép
                    let cleaned = raw.replace(/[{}"\\[\]]/g, '');
                    // Tách dấu phẩy nếu có
                    if (cleaned.includes(',')) {
                        imgs = cleaned.split(',').map(x => x.trim());
                    } else if (cleaned.trim() !== '') {
                        imgs = [cleaned.trim()];
                    }
                }
            }
        }

        // Lọc bỏ ảnh rỗng và xóa đường dẫn thừa nếu có
        item.images_url = imgs
            .filter(i => i && i.trim() !== '')
            .map(i => {
                // Nếu tên file lỡ có dính chữ "uploads/" thì xóa đi để tránh trùng lặp
                return i.replace(/^uploads\//, '').replace(/^\/uploads\//, '');
            });

        return item;
    });

    res.json(processed);
  } catch (error) {
    console.error("❌ Lỗi lấy booking:", error);
    res.status(500).json({ error: "Lỗi server" });
  }
});

// =============================================================
// ===== 1. API LẤY DANH SÁCH CHO ADMIN (FIX LỖI UNDEFINED TÊN) =====
// =============================================================
app.get("/api/admin/bookings", authorize(["admin", "staff"]), async (req, res) => {
  try {
    const sql = `
      SELECT 
        b.id, 
        b.booking_code, 
        b.created_at, 
        b.check_in, 
        b.check_out, 
        b.total_amount, 
        b.status,
        -- FIX LỖI UNDEFINED: Nếu full_name null thì lấy username, nếu null nữa thì lấy 'Khách'
        COALESCE(u.full_name, u.username, 'Khách ẩn danh') AS customer_name,
        COALESCE(u.phone, '---') AS customer_phone,
        COALESCE(res.name, 'Resort đã xóa') AS resort_name,
        COALESCE(rt.name, 'Phòng đã xóa') AS room_type
      FROM bookings b
      LEFT JOIN users u ON b.user_id = u.id
      LEFT JOIN rooms r ON b.room_id = r.id
      LEFT JOIN resorts res ON r.resort_id = res.id
      LEFT JOIN room_types rt ON r.room_type_id = rt.id
      ORDER BY b.created_at DESC
    `;
    const { rows } = await pool.query(sql);
    res.json(rows);
  } catch (error) {
    console.error("❌ Lỗi booking admin:", error);
    res.status(500).json({ error: "Lỗi server: " + error.message });
  }
});

// =============================================================
// ===== 2. API DUYỆT/HỦY ĐƠN (ĐÃ CÓ TRIGGER HỖ TRỢ) =====
// =============================================================
app.put("/api/admin/bookings/:id/status", authorize(["admin", "staff"]), async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  // Validate đầu vào
  if (!['confirmed', 'cancelled', 'checked_in', 'checked_out'].includes(status)) {
    return res.status(400).json({ error: "Trạng thái không hợp lệ" });
  }

  try {
    // Chỉ cần update Booking, Trigger trong DB sẽ tự update Room
    const sql = `
      UPDATE bookings 
      SET status = $1, updated_at = NOW() 
      WHERE id = $2 
      RETURNING id, status
    `;
    const { rows } = await pool.query(sql, [status, id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: "Không tìm thấy đơn đặt phòng" });
    }

    res.json({ message: "Cập nhật thành công!", booking: rows[0] });

  } catch (error) {
    console.error("❌ Lỗi cập nhật:", error.message);
    res.status(500).json({ error: "Lỗi server: " + error.message });
  }
});
app.put("/api/admin/bookings/:id/status", authorize(["admin", "staff"]), async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  // 1. Cập nhật Booking
  const bookingRes = await pool.query(
    `UPDATE bookings SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING room_id, status`,
    [status, id]
  );
  
  if (bookingRes.rows.length === 0) return res.status(404).json({ error: "Lỗi" });

  // 2. TỰ CẬP NHẬT LUÔN TRẠNG THÁI PHÒNG (Không cần Trigger nữa)
  const roomId = bookingRes.rows[0].room_id;
  if (status === 'confirmed') {
      await pool.query("UPDATE rooms SET status = 'reserved' WHERE id = $1", [roomId]);
  } else if (status === 'cancelled') {
      await pool.query("UPDATE rooms SET status = 'available' WHERE id = $1", [roomId]);
  }

  res.json({ message: "Thành công", booking: bookingRes.rows[0] });
});

// ===== API HỦY ĐẶT PHÒNG (CÓ CHECK 24H) =====
app.put("/api/bookings/:id/cancel", authorize(['guest']), async (req, res) => {
  const { userId } = req.user;
  const { id } = req.params;

  try {
    // BƯỚC 1: Lấy thông tin created_at để kiểm tra thời gian
    // Bạn có cột: id, user_id, status, created_at -> Đủ dùng
    const checkSql = `
      SELECT id, user_id, status, created_at 
      FROM bookings 
      WHERE id = $1
    `;
    const checkResult = await pool.query(checkSql, [id]);

    if (checkResult.rowCount === 0) {
      return res.status(404).json({ error: "Không tìm thấy đặt phòng." });
    }

    const booking = checkResult.rows[0];

    // Check quyền chính chủ
    if (booking.user_id !== userId) {
      return res.status(403).json({ error: "Bạn không có quyền hủy đơn này." });
    }

    // Check trạng thái
    if (booking.status !== 'pending' && booking.status !== 'confirmed') {
      return res.status(400).json({ error: "Không thể hủy đơn này (đã hoàn thành hoặc đã hủy)." });
    }

    // --- LOGIC 24H DỰA TRÊN CỘT CREATED_AT CỦA BẠN ---
    const createdTime = new Date(booking.created_at).getTime(); 
    const currentTime = new Date().getTime();
    const hoursDiff = (currentTime - createdTime) / (1000 * 60 * 60);

    if (hoursDiff >= 24) {
      return res.status(400).json({ 
        error: "Đã quá 24h kể từ lúc đặt (created_at). Bạn không thể hủy vé này nữa." 
      });
    }

    // BƯỚC 2: Cập nhật status
    // Cập nhật cả updated_at để biết thời điểm hủy
    const updateSql = `
      UPDATE bookings
      SET status = 'cancelled', updated_at = NOW()
      WHERE id = $1
      RETURNING id, status, updated_at;
    `;

    const { rows } = await pool.query(updateSql, [id]);

    res.status(200).json({
      message: "Hủy đặt phòng thành công!",
      booking: rows[0]
    });

  } catch (error) {
    console.error("❌ Lỗi:", error);
    res.status(500).json({ error: "Lỗi server." });
  }
});

// ===== VOUCHER API =====
app.get("/api/discounts", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, code, name, description, discount_type, value, valid_from, valid_until, status,
              usage_limit, usage_used FROM discounts ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Lỗi:", error);
    res.status(500).json({ error: "Lỗi server", details: error.message });
  }
});

app.post("/api/discounts", authorize(["admin", "staff"]), async (req, res) => {
  try {
    const { code = "", name = "", description = "", discount_type = "percent", value = null,
            valid_from, valid_until, status = "active", usage_limit = 0 } = req.body || {};

    if (!code || !discount_type || value == null || !valid_until) {
      return res.status(400).json({ error: "Thiếu dữ liệu voucher!" });
    }

    const validFrom = valid_from && String(valid_from).trim() !== ""
      ? String(valid_from).slice(0, 10) : new Date().toISOString().slice(0, 10);
    const validUntil = String(valid_until).slice(0, 10);

    const { rows } = await pool.query(
      `INSERT INTO discounts (code, name, description, discount_type, value, valid_from, valid_until,
                              status, usage_limit, usage_used, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, NOW(), NOW()) RETURNING *`,
      [code.trim(), name || null, description || null, discount_type, Number(value),
       validFrom, validUntil, status, Number(usage_limit) || 0]
    );

    res.status(201).json({ message: "Thêm voucher thành công", data: rows[0] });
  } catch (err) {
    console.error("❌ Lỗi:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

app.put("/api/discounts/:id", authorize(["admin", "staff"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { code, name, description, discount_type, value, valid_from, valid_until, status, usage_limit } = req.body;

    const { rows } = await pool.query(
      `UPDATE discounts SET code=$1, name=$2, description=$3, discount_type=$4, value=$5,
                           valid_from=$6, valid_until=$7, status=$8, usage_limit=$9, updated_at=NOW()
       WHERE id=$10 RETURNING *`,
      [code, name, description, discount_type, Number(value), valid_from, valid_until, status, Number(usage_limit) || 0, id]
    );

    if (rows.length === 0) return res.status(404).json({ error: "Không tìm thấy voucher" });

    res.json({ message: "Cập nhật voucher thành công", data: rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

app.delete("/api/discounts/:id", authorize(["admin", "staff"]), async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query("DELETE FROM discounts WHERE id=$1 RETURNING *", [id]);

    if (result.rowCount === 0) return res.status(404).json({ error: "Không tìm thấy voucher" });

    res.json({ message: "Xóa voucher thành công" });
  } catch (err) {
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

app.get("/api/revenue/filter", async (req, res) => {
  try {
    const { month, year } = req.query;
    let query = "SELECT COALESCE(SUM(total_amount), 0)::BIGINT AS total_revenue FROM bookings WHERE status = 'confirmed'";
    const params = [];

    if (month && year) {
      query += ` AND EXTRACT(MONTH FROM check_in) = $1 AND EXTRACT(YEAR FROM check_in) = $2`;
      params.push(parseInt(month), parseInt(year));
    }

    const result = await pool.query(query, params);
    res.json({ total_revenue: Number(result.rows[0].total_revenue) });
  } catch (err) {
    res.status(500).json({ error: "Lỗi server" });
  }
});

app.get("/api/bookings/filter", async (req, res) => {
  try {
    const { month, year } = req.query;
    let query = "SELECT COUNT(*) AS total FROM bookings WHERE 1=1";
    const params = [];

    if (month && year) {
      query += ` AND EXTRACT(MONTH FROM check_in) = $1 AND EXTRACT(YEAR FROM check_in) = $2`;
      params.push(parseInt(month), parseInt(year));
    }

    const result = await pool.query(query, params);
    res.json({ total: Number(result.rows[0].total) });
  } catch (err) {
    res.status(500).json({ error: "Lỗi server" });
  }
});

const PORT = process.env.PORT || 5500;
app.listen(PORT, () => {
  console.log(`✅ Server đang chạy tại http://localhost:${PORT}`);
});