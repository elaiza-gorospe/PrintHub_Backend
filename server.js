require("dotenv").config();

const express = require("express");
const prisma = require("./db/prisma");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST || "127.0.0.1",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "printhub_db",
});

db.connect((err) => {
  if (err) {
    console.error("DB ERROR:", err);
  } else {
    console.log("Connected to MySQL");
  }
});

const roleToDb = (role = "customer") => {
  if (role === "admin") return 0;
  if (role === "staff") return 1;
  return 2;
};

const roleFromDb = (num) => {
  if (num === 0) return "admin";
  if (num === 1) return "staff";
  return "customer";
};

const otpStore = {};
let transporter = null;

if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  transporter.verify((err, success) => {
    if (err) console.log("❌ Email transporter verify failed:", err);
    else console.log("✅ Email transporter ready:", success);
  });
} else {
  console.log(
    "⚠️ EMAIL_USER/EMAIL_PASS not set. OTP will be logged to console (dev mode).",
  );
}

// login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (user) {
      const match = await bcrypt.compare(password, user.password);
      if (!match)
        return res.status(400).json({ message: "Incorrect password" });

      await prisma.user.update({
        where: { id: user.id },
        data: { last_login: new Date() },
      });

      return res.json({
        message: "Login successful",
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          role: roleFromDb(user.role),
        },
      });
    }

    const archivedUser = await prisma.archivedUser.findFirst({
      where: { email },
    });
    if (!archivedUser)
      return res.status(400).json({ message: "Email not registered" });

    const matchArchived = await bcrypt.compare(password, archivedUser.password);
    if (!matchArchived)
      return res.status(400).json({ message: "Incorrect password" });

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    otpStore[email] = {
      code,
      expiresAt,
      verifiedUntil: null,
      purpose: "reactivate",
    };

    if (transporter) {
      try {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Account Reactivation OTP",
          text: `Your reactivation OTP is: ${code}. It expires in 5 minutes.`,
        });
      } catch (e) {
        console.log("EMAIL SEND ERROR:", e);
        return res
          .status(500)
          .json({ message: "Failed to send reactivation OTP" });
      }
    } else {
      console.log(
        `DEV Reactivation OTP for ${email}: ${code} (expires: ${expiresAt.toISOString()})`,
      );
    }

    return res
      .status(403)
      .json({
        message: "This account is archived. OTP sent for reactivation.",
        needsReactivation: true,
      });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Database error" });
  }
});

app.post("/api/reactivate/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp)
    return res.status(400).json({ message: "Email and OTP required" });

  const entry = otpStore[email];
  if (!entry || entry.purpose !== "reactivate") {
    return res.status(400).json({
      message: "No reactivation OTP request found. Try logging in again.",
    });
  }

  const now = new Date();
  if (now > entry.expiresAt) {
    delete otpStore[email];
    return res
      .status(400)
      .json({ message: "OTP expired. Please login again to resend OTP." });
  }

  if (String(otp) !== entry.code) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  // Move back from archived_users -> users
  db.beginTransaction((err) => {
    if (err) return res.status(500).json({ message: "DB transaction error" });

    db.query(
      "SELECT * FROM archived_users WHERE email=?",
      [email],
      (err1, rows) => {
        if (err1)
          return db.rollback(() =>
            res.status(500).json({ message: "DB error" }),
          );
        if (rows.length === 0)
          return db.rollback(() =>
            res.status(404).json({ message: "Archived account not found" }),
          );

        const u = rows[0];

        db.query(
          `INSERT INTO users
         (id, first_name, last_name, phone, address, email, password, role, status, last_login, join_date, gender, birthday, position)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [
            u.id,
            u.first_name,
            u.last_name,
            u.phone,
            u.address,
            u.email,
            u.password,
            u.role,
            "active", // ✅ reactivate as active
            u.last_login,
            u.join_date,
            u.gender,
            u.birthday,
            u.position,
          ],
          (err2) => {
            if (err2)
              return db.rollback(() =>
                res
                  .status(500)
                  .json({ message: "Restore failed", error: err2 }),
              );

            db.query(
              "DELETE FROM archived_users WHERE email=?",
              [email],
              (err3) => {
                if (err3)
                  return db.rollback(() =>
                    res
                      .status(500)
                      .json({ message: "Archive cleanup failed", error: err3 }),
                  );

                db.commit((err4) => {
                  if (err4)
                    return db.rollback(() =>
                      res
                        .status(500)
                        .json({ message: "Commit failed", error: err4 }),
                    );

                  delete otpStore[email];
                  return res.json({
                    message: "Account reactivated. Please login again.",
                    reactivated: true,
                  });
                });
              },
            );
          },
        );
      },
    );
  });
});

// =================================================
// REGISTER: SEND OTP  (UPDATED ONLY OTP LOGIC)
// =================================================
app.post("/api/register/send-otp", (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email is required" });

  prisma.user
    .findUnique({ where: { email } })
    .then(async (existing) => {
      if (existing)
        return res.status(400).json({ message: "Email already registered" });

      const code = String(Math.floor(100000 + Math.random() * 900000));
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

      otpStore[email] = { code, expiresAt, verifiedUntil: null };

      if (transporter) {
        try {
          await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your OTP Code (Registration)",
            text: `Your OTP is: ${code}. It expires in 5 minutes.`,
          });
          return res.status(200).json({ message: "OTP sent to your email." });
        } catch (e) {
          console.log("EMAIL SEND ERROR:", e);
          return res.status(500).json({ message: "Failed to send OTP email" });
        }
      } else {
        console.log(
          `DEV OTP for ${email}: ${code} (expires: ${expiresAt.toISOString()})`,
        );
        return res
          .status(200)
          .json({ message: "OTP generated (dev mode). Check server console." });
      }
    })
    .catch((e) => {
      console.error(e);
      return res.status(500).json({ message: "Database error" });
    });
});

// =================================================
// REGISTER: VERIFY OTP (ADDED for User-otp.js)
// =================================================
app.post("/api/register/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp)
    return res.status(400).json({ message: "Email and OTP required" });

  const entry = otpStore[email];
  if (!entry)
    return res
      .status(400)
      .json({ message: "No OTP request found. Please resend OTP." });

  const now = new Date();
  if (now > entry.expiresAt) {
    delete otpStore[email];
    return res.status(400).json({ message: "OTP expired. Please resend OTP." });
  }

  if (String(otp) !== entry.code) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  entry.verifiedUntil = new Date(Date.now() + 10 * 60 * 1000);
  return res.json({ message: "OTP verified" });
});

// =================================================
// NEW: SEND OTP (Password) - for frontend calling /api/password/send-otp
// =================================================
app.post("/api/password/send-otp", (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email is required" });

  db.query("SELECT id FROM users WHERE email=?", [email], async (err, rows) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (rows.length === 0)
      return res.status(404).json({ message: "Email not found" });

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    otpStore[email] = { code, expiresAt, verifiedUntil: null };

    if (transporter) {
      try {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Your OTP Code (Password Change)",
          text: `Your OTP is: ${code}. It expires in 5 minutes.`,
        });

        return res.json({ message: "OTP sent to your email." });
      } catch (e) {
        console.log("EMAIL SEND ERROR:", e);
        return res.status(500).json({ message: "Failed to send OTP email" });
      }
    } else {
      console.log(
        `DEV OTP for ${email}: ${code} (expires: ${expiresAt.toISOString()})`,
      );
      return res.json({
        message: "OTP generated (dev mode). Check server console.",
      });
    }
  });
});

// registration
app.post("/api/register/complete", async (req, res) => {
  const { firstName, lastName, email, phone, address, password } = req.body;

  if (phone && !/^\+639\d{9}$/.test(phone)) {
    return res
      .status(400)
      .json({ message: "Phone must be +639 followed by 9 digits" });
  }

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const entry = otpStore[email];
  if (!entry || !entry.verifiedUntil) {
    return res.status(403).json({ message: "OTP verification required" });
  }

  if (new Date() > new Date(entry.verifiedUntil)) {
    delete otpStore[email];
    return res
      .status(403)
      .json({ message: "OTP session expired. Please verify again." });
  }

  try {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing)
      return res.status(400).json({ message: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);

    await prisma.user.create({
      data: {
        first_name: firstName,
        last_name: lastName,
        email,
        password: hash,
        phone: phone || "+63",
        address: address || "",
        role: 2,
        join_date: new Date(),
        status: "active",
      },
    });

    delete otpStore[email];
    return res.json({ message: "Registration successful" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Registration failed" });
  }
});

// admin manage user
app.get("/api/admin/users", async (req, res) => {
  try {
    const rows = await prisma.user.findMany();
    const mapped = rows.map((u) => ({
      id: u.id,
      name: `${u.first_name} ${u.last_name}`,
      email: u.email,
      role: roleFromDb(u.role),
      status: u.status || "active",
      lastLogin: u.last_login,
      joinDate: u.join_date,
    }));
    res.json(mapped);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "DB error" });
  }
});
app.post("/api/admin/users", (req, res) => {
  const { name, email, password, role } = req.body;

  const parts = name.split(" ");
  const first = parts[0];
  const last = parts.slice(1).join(" ");
  bcrypt.hash(password, 10, async (err, hash) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Password hash error" });
    }
    try {
      await prisma.user.create({
        data: {
          first_name: first,
          last_name: last,
          email,
          password: hash,
          role: roleToDb(role),
        },
      });
      return res.json({ message: "User created" });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ message: "User create failed" });
    }
  });
});

app.put("/api/admin/users/:id", (req, res) => {
  const { name, email, role, status } = req.body;
  const parts = name.split(" ");
  const first = parts[0];
  const last = parts.slice(1).join(" ");
  prisma.user
    .update({
      where: { id: parseInt(req.params.id) },
      data: {
        first_name: first,
        last_name: last,
        email,
        role: roleToDb(role),
        status,
      },
    })
    .then(() => res.json({ message: "User updated" }))
    .catch((e) => {
      console.error(e);
      res.status(500).json({ message: "User update failed" });
    });
});

app.delete("/api/admin/users/:id", async (req, res) => {
  const userId = parseInt(req.params.id);
  try {
    const u = await prisma.user.findUnique({ where: { id: userId } });
    if (!u) return res.status(404).json({ message: "User not found" });

    await prisma.$transaction([
      prisma.archivedUser.create({
        data: {
          user_id: u.id,
          first_name: u.first_name,
          last_name: u.last_name,
          phone: u.phone,
          address: u.address,
          email: u.email,
          password: u.password,
          role: u.role,
          status: u.status,
          last_login: u.last_login,
          join_date: u.join_date,
          gender: u.gender,
          birthday: u.birthday,
          position: u.position,
          archived_at: new Date(),
        },
      }),
      prisma.user.delete({ where: { id: userId } }),
    ]);

    return res.json({ message: "User archived" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Archive failed" });
  }
});

// user cus prof
app.get("/api/user-profile/:id", (req, res) => {
  prisma.user
    .findUnique({ where: { id: parseInt(req.params.id) } })
    .then((u) => {
      if (!u) return res.status(404).json({ message: "User not found" });
      res.json({
        name: `${u.first_name} ${u.last_name}`,
        birthday: u.birthday
          ? new Date(u.birthday).toISOString().slice(0, 10)
          : "",
        gender: u.gender || "",
        phone: u.phone || "+63",
        address: u.address || "",
      });
    })
    .catch((e) => {
      console.error(e);
      res.status(500).json({ message: "DB error" });
    });
});

app.put("/api/user-profile/:id", async (req, res) => {
  const { name, email, birthday, gender, phone, address } = req.body;

  if (!/^\+639\d{9}$/.test(phone))
    return res
      .status(400)
      .json({ message: "Phone must be +639 followed by 9 digits" });

  if (birthday) {
    const y = new Date(birthday).getFullYear();
    if (y > 2011)
      return res
        .status(400)
        .json({ message: "Only users born in 2011 or earlier allowed" });
  }

  // if email is provided, validate format
  if (email && !/\S+@\S+\.\S+/.test(String(email))) {
    return res
      .status(400)
      .json({ message: "Please enter a valid email address" });
  }

  const parts = String(name || "").split(" ");
  const first = parts[0] || "";
  const last = parts.slice(1).join(" ") || "";

  // if email is provided, prevent duplicates (exclude same user id)
  if (email) {
    try {
      const dup = await prisma.user.findFirst({
        where: { email, id: { not: parseInt(req.params.id) } },
      });
      if (dup)
        return res.status(400).json({ message: "Email already registered" });

      await prisma.user.update({
        where: { id: parseInt(req.params.id) },
        data: {
          first_name: first,
          last_name: last,
          email,
          birthday,
          gender,
          phone,
          address,
        },
      });
      return res.json({ message: "Profile updated" });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ message: "Database error" });
    }
  }

  // if no email provided
  try {
    await prisma.user.update({
      where: { id: parseInt(req.params.id) },
      data: {
        first_name: first,
        last_name: last,
        birthday,
        gender,
        phone,
        address,
      },
    });
    return res.json({ message: "Profile updated" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Database error" });
  }
});

// req pass(change pass)
app.post("/api/password/request-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email is required" });

  try {
    const u = await prisma.user.findUnique({ where: { email } });
    if (!u) return res.status(404).json({ message: "Email not found" });

    const code = String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    otpStore[email] = { code, expiresAt, verifiedUntil: null };

    if (transporter) {
      try {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Your OTP Code (Password Change)",
          text: `Your OTP is: ${code}. It expires in 5 minutes.`,
        });

        return res.json({ message: "OTP sent to your email." });
      } catch (e) {
        console.log("EMAIL SEND ERROR:", e);
        return res.status(500).json({ message: "Failed to send OTP email" });
      }
    } else {
      console.log(
        `DEV OTP for ${email}: ${code} (expires: ${expiresAt.toISOString()})`,
      );
      return res.json({
        message: "OTP generated (dev mode). Check server console.",
      });
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Database error" });
  }
});

// VERIFY OTP (for password change)
app.post("/api/password/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp)
    return res.status(400).json({ message: "Email and OTP required" });

  const entry = otpStore[email];
  if (!entry)
    return res
      .status(400)
      .json({ message: "No OTP request found. Please resend OTP." });

  const now = new Date();
  if (now > entry.expiresAt) {
    delete otpStore[email];
    return res.status(400).json({ message: "OTP expired. Please resend OTP." });
  }

  if (String(otp) !== entry.code) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  entry.verifiedUntil = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
  return res.json({ message: "OTP verified" });
});

app.post("/api/password/send-otp", (req, res) => {
  req.url = "/api/password/request-otp";
  app._router.handle(req, res);
});

// CHANGE PASSWORD (requires OTP verified)
app.put("/api/profile/:id/password", async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  const upper = /[A-Z]/.test(newPassword);
  const num = /\d/.test(newPassword);
  const spec = /[^A-Za-z0-9]/.test(newPassword);
  const len = newPassword.length >= 8 && newPassword.length <= 12;

  if (!upper || !num || !spec || !len)
    return res.status(400).json({ message: "Password weak" });

  try {
    const row = await prisma.user.findUnique({
      where: { id: parseInt(req.params.id) },
    });
    if (!row) return res.status(404).json({ message: "User not found" });

    const userEmail = row.email;
    const entry = otpStore[userEmail];
    if (!entry || !entry.verifiedUntil)
      return res.status(403).json({ message: "OTP verification required" });
    if (new Date() > new Date(entry.verifiedUntil)) {
      delete otpStore[userEmail];
      return res
        .status(403)
        .json({ message: "OTP session expired. Please verify again." });
    }

    const match = await bcrypt.compare(currentPassword, row.password);
    if (!match) return res.status(400).json({ message: "Wrong password" });

    const hash = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: parseInt(req.params.id) },
      data: { password: hash },
    });
    delete otpStore[userEmail];
    return res.json({ message: "Password changed" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Database error" });
  }
});

// reset pass
app.post("/api/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword)
    return res
      .status(400)
      .json({ message: "Email and newPassword are required" });

  const entry = otpStore[email];
  if (!entry || !entry.verifiedUntil)
    return res.status(403).json({ message: "OTP verification required" });
  if (new Date() > new Date(entry.verifiedUntil)) {
    delete otpStore[email];
    return res
      .status(403)
      .json({ message: "OTP session expired. Please verify again." });
  }

  const upper = /[A-Z]/.test(newPassword);
  const num = /\d/.test(newPassword);
  const spec = /[^A-Za-z0-9]/.test(newPassword);
  const len = newPassword.length >= 8 && newPassword.length <= 12;
  if (!upper || !num || !spec || !len)
    return res.status(400).json({ message: "Password weak" });

  try {
    const hash = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({ where: { email }, data: { password: hash } });
    delete otpStore[email];
    return res.json({ message: "Password reset successful" });
  } catch (e) {
    if (e.code === "P2025")
      return res.status(404).json({ message: "Email not found" });
    console.error(e);
    return res.status(500).json({ message: "Database error" });
  }
});

// START SERVER
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
