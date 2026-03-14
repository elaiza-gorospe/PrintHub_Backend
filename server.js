require("dotenv").config();

const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
  host: '127.0.0.1',
  user: 'root',
  password: 'root',
  database: 'printhub_db'
});

db.connect(err => {
  if (err) {
    console.error("DB ERROR:", err);
    return;
  }
  console.log("Connected to MySQL");
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
  console.log("⚠️ EMAIL_USER/EMAIL_PASS not set. OTP will be logged to console (dev mode).");
}

// login
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });

  // 1) check active users
  db.query("SELECT * FROM users WHERE email=?", [email], (err, rows) => {
    if (err) return res.status(500).json({ message: "Database error" });

    if (rows.length > 0) {
      const user = rows[0];

      return bcrypt.compare(password, user.password, (err2, match) => {
        if (!match) return res.status(400).json({ message: "Incorrect password" });

        db.query("UPDATE users SET last_login=NOW() WHERE id=?", [user.id]);

        return res.json({
          message: "Login successful",
          user: {
            id: user.id,
            email: user.email,
            firstName: user.first_name,
            role: roleFromDb(user.role),
          },
        });
      });
    }

    // 2) if not found in users, check archived_users
    db.query("SELECT * FROM archived_users WHERE email=?", [email], (errA, arows) => {
      if (errA) return res.status(500).json({ message: "Database error" });
      if (arows.length === 0) return res.status(400).json({ message: "Email not registered" });

      const archivedUser = arows[0];

      bcrypt.compare(password, archivedUser.password, async (err2, match) => {
        if (!match) return res.status(400).json({ message: "Incorrect password" });

        // ✅ send reactivation OTP
        const code = String(Math.floor(100000 + Math.random() * 900000));
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        otpStore[email] = { code, expiresAt, verifiedUntil: null, purpose: "reactivate" };

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
            return res.status(500).json({ message: "Failed to send reactivation OTP" });
          }
        } else {
          console.log(`DEV Reactivation OTP for ${email}: ${code} (expires: ${expiresAt.toISOString()})`);
        }

        return res.status(403).json({
          message: "This account is archived. OTP sent for reactivation.",
          needsReactivation: true,
        });
      });
    });
  });
});


app.post("/api/reactivate/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) return res.status(400).json({ message: "Email and OTP required" });

  const entry = otpStore[email];
  if (!entry || entry.purpose !== "reactivate") {
    return res.status(400).json({ message: "No reactivation OTP request found. Try logging in again." });
  }

  const now = new Date();
  if (now > entry.expiresAt) {
    delete otpStore[email];
    return res.status(400).json({ message: "OTP expired. Please login again to resend OTP." });
  }

  if (String(otp) !== entry.code) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  // Move back from archived_users -> users
  db.beginTransaction((err) => {
    if (err) return res.status(500).json({ message: "DB transaction error" });

    db.query("SELECT * FROM archived_users WHERE email=?", [email], (err1, rows) => {
      if (err1) return db.rollback(() => res.status(500).json({ message: "DB error" }));
      if (rows.length === 0)
        return db.rollback(() => res.status(404).json({ message: "Archived account not found" }));

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
          "active",       // ✅ reactivate as active
          u.last_login,
          u.join_date,
          u.gender,
          u.birthday,
          u.position,
        ],
        (err2) => {
          if (err2)
            return db.rollback(() =>
              res.status(500).json({ message: "Restore failed", error: err2 })
            );

          db.query("DELETE FROM archived_users WHERE email=?", [email], (err3) => {
            if (err3)
              return db.rollback(() =>
                res.status(500).json({ message: "Archive cleanup failed", error: err3 })
              );

            db.commit((err4) => {
              if (err4)
                return db.rollback(() =>
                  res.status(500).json({ message: "Commit failed", error: err4 })
                );

              delete otpStore[email];
              return res.json({ message: "Account reactivated. Please login again.", reactivated: true });
            });
          });
        }
      );
    });
  });
});



// =================================================
// REGISTER: SEND OTP  (UPDATED ONLY OTP LOGIC)
// =================================================
app.post('/api/register/send-otp', (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email is required" });

  db.query("SELECT id FROM users WHERE email=?", [email], async (err, rows) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (rows.length > 0) return res.status(400).json({ message: "Email already registered" });

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
      console.log(`DEV OTP for ${email}: ${code} (expires: ${expiresAt.toISOString()})`);
      return res.status(200).json({ message: "OTP generated (dev mode). Check server console." });
    }
  });
});

// =================================================
// REGISTER: VERIFY OTP (ADDED for User-otp.js)
// =================================================
app.post("/api/register/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) return res.status(400).json({ message: "Email and OTP required" });

  const entry = otpStore[email];
  if (!entry) return res.status(400).json({ message: "No OTP request found. Please resend OTP." });

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
    if (rows.length === 0) return res.status(404).json({ message: "Email not found" });

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
      console.log(`DEV OTP for ${email}: ${code} (expires: ${expiresAt.toISOString()})`);
      return res.json({ message: "OTP generated (dev mode). Check server console." });
    }
  });
});

// registration
app.post("/api/register/complete", (req, res) => {
  const { firstName, lastName, email, phone, address, password } = req.body;

  if (phone && !/^\+639\d{9}$/.test(phone)) {
    return res.status(400).json({ message: "Phone must be +639 followed by 9 digits" });
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
    return res.status(403).json({ message: "OTP session expired. Please verify again." });
  }

  db.query("SELECT id FROM users WHERE email=?", [email], (err, rows) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (rows.length > 0) return res.status(400).json({ message: "Email already registered" });

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.status(500).json({ message: "Password hash error" });

      db.query(
        "INSERT INTO users(first_name,last_name,email,password,phone,address,role,join_date,status) VALUES(?,?,?,?,?,?,2,NOW(),'active')",
        [firstName, lastName, email, hash, phone || "+63", address || ""],
        (err2) => {
          if (err2) return res.status(500).json({ message: "Registration failed" });

          delete otpStore[email];
          return res.json({ message: "Registration successful" });
        }
      );
    });
  });
});

// admin manage user
app.get("/api/admin/users", (req, res) => {
  db.query("SELECT * FROM users", (err, rows) => {
    if (err) return res.status(500).json({ message: "DB error" });

    const mapped = rows.map(u => ({
      id: u.id,
      name: `${u.first_name} ${u.last_name}`,
      email: u.email,
      role: roleFromDb(u.role),
      status: u.status || "active",
      lastLogin: u.last_login,
      joinDate: u.join_date
    }));

    res.json(mapped);
  });
});
app.post("/api/admin/users", (req, res) => {
  const { name, email, password, role } = req.body;

  const parts = name.split(" ");
  const first = parts[0];
  const last = parts.slice(1).join(" ");

  bcrypt.hash(password, 10, (err, hash) => {
    db.query(
      "INSERT INTO users(first_name,last_name,email,password,role) VALUES(?,?,?,?,?)",
      [first, last, email, hash, roleToDb(role)],
      () => res.json({ message: "User created" })
    );
  });
});

app.put("/api/admin/users/:id", (req, res) => {
  const { name, email, role, status } = req.body;
  const parts = name.split(" ");
  const first = parts[0];
  const last = parts.slice(1).join(" ");

  db.query(
    "UPDATE users SET first_name=?,last_name=?,email=?,role=?,status=? WHERE id=?",
    [first, last, email, roleToDb(role), status, req.params.id],
    () => res.json({ message: "User updated" })
  );
});

app.delete("/api/admin/users/:id", (req, res) => {
  const userId = req.params.id;

  db.beginTransaction((err) => {
    if (err) return res.status(500).json({ message: "DB transaction error" });

    db.query("SELECT * FROM users WHERE id=?", [userId], (err1, rows) => {
      if (err1) return db.rollback(() => res.status(500).json({ message: "DB error" }));
      if (rows.length === 0)
        return db.rollback(() => res.status(404).json({ message: "User not found" }));

      const u = rows[0];

      db.query(
        `INSERT INTO archived_users
         (user_id, first_name, last_name, phone, address, email, password, role, status, last_login, join_date, gender, birthday, position, archived_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NOW())`,
        [
          u.id,
          u.first_name,
          u.last_name,
          u.phone,
          u.address,
          u.email,
          u.password,
          u.role,
          u.status,
          u.last_login,
          u.join_date,
          u.gender,
          u.birthday,
          u.position,
        ],
        (err2) => {
          if (err2) {
            console.log("ARCHIVE INSERT ERROR:", err2);
            return db.rollback(() =>
              res.status(500).json({ message: "Archive insert failed", error: err2 })
            );
          }

          db.query("DELETE FROM users WHERE id=?", [userId], (err3) => {
            if (err3)
              return db.rollback(() =>
                res.status(500).json({ message: "Delete failed", error: err3 })
              );

            db.commit((err4) => {
              if (err4)
                return db.rollback(() =>
                  res.status(500).json({ message: "Commit failed" })
                );

              return res.json({ message: "User archived" });
            });
          });
        }
      );
    });
  });
});


// user cus prof
app.get("/api/user-profile/:id", (req, res) => {
  db.query(
    "SELECT first_name,last_name,birthday,gender,phone,address FROM users WHERE id=?",
    [req.params.id],
    (err, rows) => {
      if (rows.length === 0)
        return res.status(404).json({ message: "User not found" });

      const u = rows[0];
      res.json({
        name: `${u.first_name} ${u.last_name}`,
        birthday: u.birthday
          ? new Date(u.birthday).toISOString().slice(0, 10)
          : "",
        gender: u.gender || "",
        phone: u.phone || "+63",
        address: u.address || ""
      });
    }
  );
});

app.put("/api/user-profile/:id", (req, res) => {
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
    return res.status(400).json({ message: "Please enter a valid email address" });
  }

  const parts = String(name || "").split(" ");
  const first = parts[0] || "";
  const last = parts.slice(1).join(" ") || "";

  // if email is provided, prevent duplicates (exclude same user id)
  if (email) {
    db.query(
      "SELECT id FROM users WHERE email=? AND id<>?",
      [email, req.params.id],
      (errDup, rowsDup) => {
        if (errDup) return res.status(500).json({ message: "Database error" });
        if (rowsDup.length > 0) {
          return res.status(400).json({ message: "Email already registered" });
        }

        db.query(
          `UPDATE users 
           SET first_name=?,last_name=?,email=?,birthday=?,gender=?,phone=?,address=?
           WHERE id=?`,
          [first, last, email, birthday, gender, phone, address, req.params.id],
          () => res.json({ message: "Profile updated" })
        );
      }
    );
    return;
  }

  // if no email provided, keep old behavior
  db.query(
    `UPDATE users 
     SET first_name=?,last_name=?,birthday=?,gender=?,phone=?,address=?
     WHERE id=?`,
    [first, last, birthday, gender, phone, address, req.params.id],
    () => res.json({ message: "Profile updated" })
  );
});

// req pass(change pass)
app.post("/api/password/request-otp", (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email is required" });

  db.query("SELECT id FROM users WHERE email=?", [email], async (err, rows) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (rows.length === 0) return res.status(404).json({ message: "Email not found" });

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
      console.log(`DEV OTP for ${email}: ${code} (expires: ${expiresAt.toISOString()})`);
      return res.json({ message: "OTP generated (dev mode). Check server console." });
    }
  });
});

// VERIFY OTP (for password change)
app.post("/api/password/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) return res.status(400).json({ message: "Email and OTP required" });

  const entry = otpStore[email];
  if (!entry) return res.status(400).json({ message: "No OTP request found. Please resend OTP." });

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
app.put("/api/profile/:id/password", (req, res) => {
  const { currentPassword, newPassword } = req.body;

  const upper = /[A-Z]/.test(newPassword);
  const num = /\d/.test(newPassword);
  const spec = /[^A-Za-z0-9]/.test(newPassword);
  const len = newPassword.length >= 8 && newPassword.length <= 12;

  if (!upper || !num || !spec || !len)
    return res.status(400).json({ message: "Password weak" });

  db.query(
    "SELECT email,password FROM users WHERE id=?",
    [req.params.id],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Database error" });
      if (rows.length === 0) return res.status(404).json({ message: "User not found" });

      const userEmail = rows[0].email;

      const entry = otpStore[userEmail];
      if (!entry || !entry.verifiedUntil) {
        return res.status(403).json({ message: "OTP verification required" });
      }

      if (new Date() > new Date(entry.verifiedUntil)) {
        delete otpStore[userEmail];
        return res.status(403).json({ message: "OTP session expired. Please verify again." });
      }

      bcrypt.compare(currentPassword, rows[0].password, (err, match) => {
        if (!match)
          return res.status(400).json({ message: "Wrong password" });

        bcrypt.hash(newPassword, 10, (err, hash) => {
          db.query(
            "UPDATE users SET password=? WHERE id=?",
            [hash, req.params.id],
            () => {
              delete otpStore[userEmail];
              res.json({ message: "Password changed" });
            }
          );
        });
      });
    }
  );
});

// reset pass
app.post("/api/reset-password", (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({ message: "Email and newPassword are required" });
  }

  // require OTP verified first
  const entry = otpStore[email];
  if (!entry || !entry.verifiedUntil) {
    return res.status(403).json({ message: "OTP verification required" });
  }

  if (new Date() > new Date(entry.verifiedUntil)) {
    delete otpStore[email];
    return res.status(403).json({ message: "OTP session expired. Please verify again." });
  }

  // same password rules
  const upper = /[A-Z]/.test(newPassword);
  const num = /\d/.test(newPassword);
  const spec = /[^A-Za-z0-9]/.test(newPassword);
  const len = newPassword.length >= 8 && newPassword.length <= 12;

  if (!upper || !num || !spec || !len) {
    return res.status(400).json({ message: "Password weak" });
  }

  // update password by email
  bcrypt.hash(newPassword, 10, (err, hash) => {
    if (err) return res.status(500).json({ message: "Password hash error" });

    db.query("UPDATE users SET password=? WHERE email=?", [hash, email], (err2, result) => {
      if (err2) return res.status(500).json({ message: "Database error" });
      if (result.affectedRows === 0) return res.status(404).json({ message: "Email not found" });

      // clear otp after success
      delete otpStore[email];
      return res.json({ message: "Password reset successful" });
    });
  });
});


// START SERVER
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
