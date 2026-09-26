require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.use(express.json({ limit: "10mb" }));

const DEFAULT_ORIGINS = [
  "https://janzychau.github.io"
];

const ORIGIN_LIST = [
  ...DEFAULT_ORIGINS,
  ...(process.env.FRONTEND_ORIGINS || "")
    .split(",")
    .map(x => x.trim())
    .filter(Boolean)
];

function normalizeOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return String(value || "").trim().replace(/\/$/, "");
  }
}

const ALLOWED_ORIGINS = new Set(
  ORIGIN_LIST.map(normalizeOrigin).filter(Boolean)
);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);

      const normalized = normalizeOrigin(origin);

      if (
        ALLOWED_ORIGINS.has("*") ||
        ALLOWED_ORIGINS.has(normalized)
      ) {
        return cb(null, true);
      }

      console.warn(
        "CORS blocked origin:",
        origin,
        "allowed:",
        Array.from(ALLOWED_ORIGINS)
      );

      return cb(new Error("Origin not allowed"));
    },

    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS"
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ],

    optionsSuccessStatus: 204
  })
);

const PORT = Number(process.env.PORT || 10000);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY || !JWT_SECRET) {
  console.error("Missing required environment variables");
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

const OWNER = "Chủ Sở Hữu";
const ADMIN = "Quản Trị";
const MEMBER = "Thành Viên";
const VIEWER = "Người Xem";

const STATE_KEYS = [
  "sanPham",
  "danhMucTabs",
  "phieuDeXuat",
  "phieuDuyetDeXuat",
  "phieuDatHang",
  "phieuNhanHang",
  "phieuTraHang",
  "phieuHuyHang"
];

const STATE_WRITE = {
  sanPham: [OWNER, ADMIN, MEMBER],
  danhMucTabs: [OWNER, ADMIN],
  phieuDeXuat: [OWNER, ADMIN, MEMBER],
  phieuDuyetDeXuat: [OWNER, ADMIN, MEMBER],
  phieuDatHang: [OWNER, ADMIN, MEMBER],
  phieuNhanHang: [OWNER, ADMIN, MEMBER],
  phieuTraHang: [OWNER, ADMIN, MEMBER],
  phieuHuyHang: [OWNER, ADMIN, MEMBER]
};

function role(v) {
  const s = String(v || "").trim().toLowerCase();

  if (s === OWNER.toLowerCase()) return OWNER;
  if (s === ADMIN.toLowerCase()) return ADMIN;
  if (s === MEMBER.toLowerCase()) return MEMBER;

  return VIEWER;
}

function publicUser(u) {
  return {
    id: u.id,
    ma: u.ma,
    ten: u.ten,
    chuc_vu: u.chuc_vu,
    phong_ban: u.phong_ban,
    tai_khoan: u.tai_khoan,
    phan_quyen: role(u.phan_quyen),
    hieu_luc: u.hieu_luc,
    ghi_chu: u.ghi_chu
  };
}

async function getUser(id) {
  const { data, error } = await supabase
    .from("nhan_vien")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (error) throw error;

  return data;
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({
        error: "Chưa đăng nhập."
      });
    }

    const payload = jwt.verify(token, JWT_SECRET);
    const user = await getUser(payload.sub);

    if (!user || !user.hieu_luc) {
      return res.status(401).json({
        error: "Tài khoản không tồn tại hoặc đã bị khóa."
      });
    }

    req.user = user;

    next();
  } catch (e) {
    return res.status(401).json({
      error: "Phiên đăng nhập không hợp lệ hoặc đã hết hạn."
    });
  }
}

function ownerAdmin(req, res, next) {
  if (
    ![OWNER, ADMIN].includes(
      role(req.user.phan_quyen)
    )
  ) {
    return res.status(403).json({
      error: "Bạn không có quyền thực hiện thao tác này."
    });
  }

  next();
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "quanlydathang-api"
  });
});

app.get("/api/health", async (req, res) => {
  try {
    const { error } = await supabase
      .from("danh_muc")
      .select("id")
      .limit(1);

    if (error) throw error;

    res.json({
      ok: true,
      database: "connected"
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      database: "error",
      detail: e.message
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = String(
      req.body.username || ""
    ).trim();

    const password = String(
      req.body.password || ""
    );

    const { data: user, error } = await supabase
      .from("nhan_vien")
      .select("*")
      .eq("tai_khoan", username)
      .maybeSingle();

    if (error) throw error;

    if (
      !user ||
      !user.hieu_luc ||
      !user.mat_khau_hash ||
      !(await bcrypt.compare(
        password,
        user.mat_khau_hash
      ))
    ) {
      return res.status(401).json({
        error: "Tài khoản hoặc mật khẩu không đúng."
      });
    }

    const token = jwt.sign(
      {
        sub: user.id,
        tai_khoan: user.tai_khoan,
        phan_quyen: role(user.phan_quyen)
      },
      JWT_SECRET,
      {
        expiresIn: "12h"
      }
    );

    res.json({
      ok: true,
      token,
      user: publicUser(user)
    });
  } catch (e) {
    res.status(500).json({
      error: "Lỗi máy chủ khi đăng nhập.",
      detail: e.message
    });
  }
});

app.get("/api/auth/me", auth, (req, res) => {
  res.json({
    ok: true,
    user: publicUser(req.user)
  });
});

app.post(
  "/api/auth/change-password",
  auth,
  async (req, res) => {
    try {
      const oldPass = String(
        req.body.currentPassword || ""
      );

      const newPass = String(
        req.body.newPassword || ""
      );

      if (newPass.length < 6) {
        return res.status(400).json({
          error:
            "Mật khẩu mới phải có ít nhất 6 ký tự."
        });
      }

      if (
        !(await bcrypt.compare(
          oldPass,
          req.user.mat_khau_hash || ""
        ))
      ) {
        return res.status(400).json({
          error:
            "Mật khẩu hiện tại không đúng."
        });
      }

      const { error } = await supabase
        .from("nhan_vien")
        .update({
          mat_khau_hash:
            await bcrypt.hash(newPass, 12),
          updated_at:
            new Date().toISOString()
        })
        .eq("id", req.user.id);

      if (error) throw error;

      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({
        error: "Không thể đổi mật khẩu.",
        detail: e.message
      });
    }
  }
);

app.get(
  "/api/employees",
  auth,
  async (req, res) => {
    const { data, error } = await supabase
      .from("nhan_vien")
      .select(
        "id,ma,ten,chuc_vu,phong_ban,tai_khoan,phan_quyen,hieu_luc,ghi_chu,created_at,updated_at"
      )
      .order("created_at", {
        ascending: true
      });

    if (error) {
      return res.status(500).json({
        error: error.message
      });
    }

    res.json({
      data: data || []
    });
  }
);

app.post(
  "/api/employees",
  auth,
  ownerAdmin,
  async (req, res) => {
    try {
      const adminRole = role(
        req.user.phan_quyen
      );

      const newRole = role(
        req.body.phan_quyen
      );

      const password = String(
        req.body.mat_khau || ""
      );

      if (
        adminRole === ADMIN &&
        ![MEMBER, VIEWER].includes(newRole)
      ) {
        return res.status(403).json({
          error:
            "Admin chỉ được tạo Thành Viên hoặc Người Xem."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            "Mật khẩu phải có ít nhất 6 ký tự."
        });
      }

      const payload = {
        ma: req.body.ma || "",
        ten: req.body.ten || "",
        chuc_vu:
          req.body.chuc_vu || "",
        phong_ban:
          req.body.phong_ban || "",
        tai_khoan:
          req.body.tai_khoan || "",
        phan_quyen: newRole,
        hieu_luc:
          req.body.hieu_luc !== false,
        ghi_chu:
          req.body.ghi_chu || "",
        mat_khau_hash:
          await bcrypt.hash(password, 12)
      };

      const { data, error } =
        await supabase
          .from("nhan_vien")
          .insert(payload)
          .select("*")
          .single();

      if (error) throw error;

      res.status(201).json({
        data: publicUser(data)
      });
    } catch (e) {
      res.status(500).json({
        error:
          "Không thể tạo nhân viên.",
        detail: e.message
      });
    }
  }
);

app.patch(
  "/api/employees/:id",
  auth,
  ownerAdmin,
  async (req, res) => {
    try {
      const target =
        await getUser(req.params.id);

      if (!target) {
        return res.status(404).json({
          error:
            "Không tìm thấy nhân viên."
        });
      }

      const adminRole = role(
        req.user.phan_quyen
      );

      const targetRole = role(
        target.phan_quyen
      );

      if (
        !(
          adminRole === OWNER ||
          (
            adminRole === ADMIN &&
            [MEMBER, VIEWER].includes(
              targetRole
            )
          )
        )
      ) {
        return res.status(403).json({
          error:
            "Bạn không được sửa tài khoản này."
        });
      }

      const payload = {};

      [
        "ma",
        "ten",
        "chuc_vu",
        "phong_ban",
        "tai_khoan",
        "hieu_luc",
        "ghi_chu"
      ].forEach(key => {
        if (
          Object.prototype.hasOwnProperty.call(
            req.body,
            key
          )
        ) {
          payload[key] =
            req.body[key];
        }
      });

      if (
        req.body.phan_quyen !== undefined
      ) {
        const newRole = role(
          req.body.phan_quyen
        );

        if (
          adminRole === ADMIN &&
          ![MEMBER, VIEWER].includes(
            newRole
          )
        ) {
          return res.status(403).json({
            error:
              "Admin không được đổi quyền thành Owner/Admin."
          });
        }

        payload.phan_quyen =
          newRole;
      }

      if (req.body.mat_khau) {
        payload.mat_khau_hash =
          await bcrypt.hash(
            String(req.body.mat_khau),
            12
          );
      }

      payload.updated_at =
        new Date().toISOString();

      const { data, error } =
        await supabase
          .from("nhan_vien")
          .update(payload)
          .eq("id", req.params.id)
          .select("*")
          .single();

      if (error) throw error;

      res.json({
        data: publicUser(data)
      });
    } catch (e) {
      res.status(500).json({
        error:
          "Không thể cập nhật nhân viên.",
        detail: e.message
      });
    }
  }
);

app.delete(
  "/api/employees/:id",
  auth,
  ownerAdmin,
  async (req, res) => {
    try {
      if (
        req.params.id ===
        req.user.id
      ) {
        return res.status(400).json({
          error:
            "Không thể tự xóa tài khoản đang đăng nhập."
        });
      }

      const target =
        await getUser(req.params.id);

      if (!target) {
        return res.status(404).json({
          error:
            "Không tìm thấy nhân viên."
        });
      }

      const adminRole = role(
        req.user.phan_quyen
      );

      const targetRole = role(
        target.phan_quyen
      );

      if (
        !(
          adminRole === OWNER ||
          (
            adminRole === ADMIN &&
            [MEMBER, VIEWER].includes(
              targetRole
            )
          )
        )
      ) {
        return res.status(403).json({
          error:
            "Bạn không được xóa tài khoản này."
        });
      }

      const { error } =
        await supabase
          .from("nhan_vien")
          .delete()
          .eq("id", req.params.id);

      if (error) throw error;

      res.json({
        ok: true
      });
    } catch (e) {
      res.status(500).json({
        error:
          "Không thể xóa nhân viên.",
        detail: e.message
      });
    }
  }
);

app.get(
  "/api/state",
  auth,
  async (req, res) => {
    try {
      const { data, error } =
        await supabase
          .from("app_state")
          .select(
            "key,value,updated_at"
          );

      if (error) throw error;

      const state = {};

      (data || []).forEach(row => {
        state[row.key] = row.value;
      });

      res.json({
        ok: true,
        state
      });
    } catch (e) {
      res.status(500).json({
        error:
          "Không thể tải dữ liệu dùng chung.",
        detail: e.message
      });
    }
  }
);

app.put(
  "/api/state/:key",
  auth,
  async (req, res) => {
    try {
      const key = req.params.key;

      if (!STATE_KEYS.includes(key)) {
        return res.status(404).json({
          error:
            "State key không hợp lệ."
        });
      }

      const userRole = role(
        req.user.phan_quyen
      );

      if (
        !(STATE_WRITE[key] || [])
          .includes(userRole)
      ) {
        return res.status(403).json({
          error:
            "Bạn không có quyền cập nhật dữ liệu này."
        });
      }

      if (!Array.isArray(req.body)) {
        return res.status(400).json({
          error:
            "Dữ liệu phải là mảng JSON."
        });
      }

      const { error } =
        await supabase
          .from("app_state")
          .upsert(
            {
              key,
              value: req.body,
              updated_at:
                new Date().toISOString(),
              updated_by:
                req.user.id
            },
            {
              onConflict:
                "key"
            }
          );

      if (error) throw error;

      res.json({
        ok: true
      });
    } catch (e) {
      res.status(500).json({
        error:
          "Không thể lưu dữ liệu dùng chung.",
        detail: e.message
      });
    }
  }
);

app.listen(
  PORT,
  "0.0.0.0",
  () =>
    console.log(
      "quanlydathang-api listening on " +
      PORT +
      " (v1.2 fast state writes)"
    )
);
