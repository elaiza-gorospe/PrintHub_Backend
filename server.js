require("dotenv").config();

const express = require("express");
const prisma = require("./db/prisma");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

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

    return res.status(403).json({
      message: "This account is archived. OTP sent for reactivation.",
      needsReactivation: true,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Database error" });
  }
});

app.post("/api/reactivate/verify-otp", async (req, res) => {
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

  // Move back from archived_users -> users (Prisma transaction)
  try {
    const u = await prisma.archivedUser.findUnique({ where: { email } });
    if (!u)
      return res.status(404).json({ message: "Archived account not found" });

    await prisma.$transaction([
      prisma.user.create({
        data: {
          first_name: u.first_name,
          last_name: u.last_name,
          phone: u.phone,
          address: u.address,
          email: u.email,
          password: u.password,
          role: u.role ?? 2,
          status: "active",
          last_login: u.last_login,
          join_date: u.join_date,
          gender: u.gender,
          birthday: u.birthday,
          position: u.position,
        },
      }),
      prisma.archivedUser.delete({ where: { email } }),
    ]);

    delete otpStore[email];
    return res.json({
      message: "Account reactivated. Please login again.",
      reactivated: true,
    });
  } catch (err) {
    console.error(err);
    return res
      .status(500)
      .json({ message: "Restore failed", error: err.message });
  }
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

// replaced MySQL-based OTP check with Prisma-based handler below
app.post("/api/password/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email is required" });

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ message: "Email not found" });

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
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Database error" });
  }
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
        id: u.id,
        name: `${u.first_name} ${u.last_name}`,
        email: u.email || "",
        phone: u.phone || "+63",
        address: u.address || "",
        gender: u.gender || "",
        birthday: u.birthday
          ? new Date(u.birthday).toISOString().slice(0, 10)
          : "",
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

// -------------------------
// Orders API
// -------------------------
app.post("/api/orders", async (req, res) => {
  const { userId, items, shipping_address, billing_address, shippingCost } =
    req.body;

  console.log("📦 Order received:", {
    userId,
    itemsCount: items?.length,
    shippingCost,
  });
  console.log("📋 Items detail:", JSON.stringify(items, null, 2));

  if (!userId || !items || !Array.isArray(items) || items.length === 0)
    return res.status(400).json({ message: "Invalid order payload" });

  try {
    // Verify products exist
    const productIds = items.map((i) => i.productId);
    const products = await prisma.product.findMany({
      where: { id: { in: productIds } },
    });

    if (products.length !== productIds.length) {
      return res
        .status(400)
        .json({ message: "One or more products not found" });
    }

    let itemsTotal = 0;
    const createItems = items.map((it) => {
      // Use unitPrice from frontend (what customer saw at checkout)
      const unit = parseFloat(it.unitPrice || 0);
      const quantity = Number(it.quantity || 1);
      const itemTotal = unit * quantity;
      console.log(
        `  Item: productId=${it.productId}, unitPrice=${unit}, qty=${quantity}, itemTotal=${itemTotal}`,
      );
      itemsTotal += itemTotal;
      return {
        productId: it.productId,
        quantity,
        unit_price: parseFloat(unit.toFixed(2)),
        total_price: parseFloat(itemTotal.toFixed(2)),
        customizations: it.customizations || {},
      };
    });

    // Add shipping to total
    const shipping = parseFloat(shippingCost || 0);
    const total = itemsTotal + shipping;

    console.log(
      `💰 Calculation: itemsTotal=${itemsTotal}, shipping=${shipping}, total=${total}`,
    );

    const order = await prisma.order.create({
      data: {
        userId,
        total: parseFloat(total.toFixed(2)),
        currency: "PHP",
        status: "pending",
        shipping_address,
        billing_address,
        items: { create: createItems },
      },
      include: { items: true },
    });

    console.log(`✅ Order created: ID=${order.id}, total=${order.total}`);
    res.json({ message: "Order created", order });
  } catch (e) {
    console.error("❌ Order creation failed:", e.message);
    res.status(500).json({ message: "Order creation failed" });
  }
});

app.get("/api/orders/:id", async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const order = await prisma.order.findUnique({
      where: { id },
      include: { items: { include: { product: true } }, user: true },
    });
    if (!order || order.deleted_at)
      return res.status(404).json({ message: "Order not found" });
    res.json(order);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "DB error" });
  }
});

app.get("/api/user/:id/orders", async (req, res) => {
  const userId = parseInt(req.params.id);
  try {
    const orders = await prisma.order.findMany({
      where: { userId, deleted_at: null },
      include: { items: true },
    });
    res.json(orders);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "DB error" });
  }
});

app.get("/api/admin/orders", async (req, res) => {
  try {
    const orders = await prisma.order.findMany({
      where: { deleted_at: null },
      include: { items: true, user: true },
    });
    res.json(orders);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "DB error" });
  }
});

// =================================================
// PRODUCTS API
// =================================================

// GET all products with pagination
app.get("/api/products", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const products = await prisma.product.findMany({
      where: { active: true, deleted_at: null },
      skip,
      take: limit,
      orderBy: { createdAt: "desc" },
    });

    const total = await prisma.product.count({
      where: { active: true, deleted_at: null },
    });

    res.json({
      products,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to fetch products" });
  }
});

// GET single product by ID
app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await prisma.product.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { orderItems: true },
    });

    if (!product || product.deleted_at) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json(product);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to fetch product" });
  }
});

// CREATE new product (admin only)
app.post("/api/products", async (req, res) => {
  try {
    const {
      name,
      sku,
      description,
      price,
      currency,
      stock,
      width_mm,
      height_mm,
      depth_mm,
      material,
      colorOptions,
      print_type,
      turnaround_hours,
      images,
    } = req.body;

    if (!name || !price) {
      return res.status(400).json({ message: "Name and price are required" });
    }

    const product = await prisma.product.create({
      data: {
        name,
        sku,
        description,
        price: parseFloat(price),
        currency: currency || "PHP",
        stock: parseInt(stock) || 0,
        width_mm: width_mm ? parseInt(width_mm) : null,
        height_mm: height_mm ? parseInt(height_mm) : null,
        depth_mm: depth_mm ? parseInt(depth_mm) : null,
        material,
        colorOptions: colorOptions || [],
        print_type,
        turnaround_hours: turnaround_hours ? parseInt(turnaround_hours) : null,
        images: images || [],
        active: true,
      },
    });

    res.status(201).json({ message: "Product created", product });
  } catch (e) {
    console.error(e);
    if (e.code === "P2002") {
      return res.status(400).json({ message: "SKU already exists" });
    }
    res.status(500).json({ message: "Failed to create product" });
  }
});

// UPDATE product (admin only)
app.put("/api/products/:id", async (req, res) => {
  try {
    const {
      name,
      description,
      price,
      currency,
      stock,
      width_mm,
      height_mm,
      depth_mm,
      material,
      colorOptions,
      print_type,
      turnaround_hours,
      images,
      active,
    } = req.body;

    const product = await prisma.product.update({
      where: { id: parseInt(req.params.id) },
      data: {
        ...(name && { name }),
        ...(description && { description }),
        ...(price && { price: parseFloat(price) }),
        ...(currency && { currency }),
        ...(stock !== undefined && { stock: parseInt(stock) }),
        ...(width_mm !== undefined && {
          width_mm: width_mm ? parseInt(width_mm) : null,
        }),
        ...(height_mm !== undefined && {
          height_mm: height_mm ? parseInt(height_mm) : null,
        }),
        ...(depth_mm !== undefined && {
          depth_mm: depth_mm ? parseInt(depth_mm) : null,
        }),
        ...(material && { material }),
        ...(colorOptions && { colorOptions }),
        ...(print_type && { print_type }),
        ...(turnaround_hours !== undefined && {
          turnaround_hours: turnaround_hours
            ? parseInt(turnaround_hours)
            : null,
        }),
        ...(images && { images }),
        ...(active !== undefined && { active }),
      },
    });

    res.json({ message: "Product updated", product });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025") {
      return res.status(404).json({ message: "Product not found" });
    }
    res.status(500).json({ message: "Failed to update product" });
  }
});

// DELETE product (soft delete via deleted_at field)
app.delete("/api/products/:id", async (req, res) => {
  try {
    const product = await prisma.product.update({
      where: { id: parseInt(req.params.id) },
      data: { deleted_at: new Date() },
    });

    res.json({ message: "Product deleted", product });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025") {
      return res.status(404).json({ message: "Product not found" });
    }
    res.status(500).json({ message: "Failed to delete product" });
  }
});

// =================================================
// ORDERS API
// =================================================

// CREATE new order with items
app.post("/api/orders", async (req, res) => {
  try {
    const { userId, items, shipping_address, billing_address } = req.body;

    if (!userId || !items || items.length === 0) {
      return res.status(400).json({ message: "userId and items are required" });
    }

    // Verify user exists
    const user = await prisma.user.findUnique({
      where: { id: parseInt(userId) },
    });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Calculate total and create order with items
    let total = 0;
    const orderItems = [];

    for (const item of items) {
      const product = await prisma.product.findUnique({
        where: { id: parseInt(item.productId) },
      });

      if (!product) {
        return res
          .status(404)
          .json({ message: `Product ${item.productId} not found` });
      }

      const unitPrice = parseFloat(product.price);
      const quantity = parseInt(item.quantity) || 1;
      const itemTotal = unitPrice * quantity;

      total += itemTotal;

      orderItems.push({
        productId: parseInt(item.productId),
        quantity,
        unit_price: unitPrice,
        total_price: itemTotal,
        customizations: item.customizations || null,
      });
    }

    // Create order with items in transaction
    const order = await prisma.order.create({
      data: {
        userId: parseInt(userId),
        total: parseFloat(total.toFixed(2)),
        currency: "PHP",
        status: "pending",
        shipping_address,
        billing_address,
        items: {
          create: orderItems,
        },
      },
      include: { items: true, user: true },
    });

    res.status(201).json({ message: "Order created", order });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to create order" });
  }
});

// GET order by ID
app.get("/api/orders/:id", async (req, res) => {
  try {
    const order = await prisma.order.findUnique({
      where: { id: parseInt(req.params.id) },
      include: {
        items: {
          include: { product: true },
        },
        user: true,
      },
    });

    if (!order || order.deleted_at) {
      return res.status(404).json({ message: "Order not found" });
    }

    res.json(order);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to fetch order" });
  }
});

// UPDATE order status
app.put("/api/orders/:id", async (req, res) => {
  try {
    const {
      status,
      proofApproved,
      due_date,
      shipping_address,
      billing_address,
    } = req.body;

    const order = await prisma.order.update({
      where: { id: parseInt(req.params.id) },
      data: {
        ...(status && { status }),
        ...(proofApproved !== undefined && { proofApproved }),
        ...(due_date && { due_date: new Date(due_date) }),
        ...(shipping_address && { shipping_address }),
        ...(billing_address && { billing_address }),
      },
      include: { items: true, user: true },
    });

    res.json({ message: "Order updated", order });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025") {
      return res.status(404).json({ message: "Order not found" });
    }
    res.status(500).json({ message: "Failed to update order" });
  }
});

// MARK order as delivered
app.patch("/api/orders/:id/deliver", async (req, res) => {
  try {
    const order = await prisma.order.update({
      where: { id: parseInt(req.params.id) },
      data: {
        status: "delivered",
        delivered_at: new Date(),
      },
      include: { items: true, user: true },
    });

    res.json({ message: "Order marked as delivered", order });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025") {
      return res.status(404).json({ message: "Order not found" });
    }
    res.status(500).json({ message: "Failed to deliver order" });
  }
});

// DELETE order (soft delete)
app.delete("/api/orders/:id", async (req, res) => {
  try {
    const order = await prisma.order.update({
      where: { id: parseInt(req.params.id) },
      data: { deleted_at: new Date() },
      include: { items: true, user: true },
    });

    res.json({ message: "Order deleted", order });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025") {
      return res.status(404).json({ message: "Order not found" });
    }
    res.status(500).json({ message: "Failed to delete order" });
  }
});

// DELETE order item
app.delete("/api/orders/:orderId/items/:itemId", async (req, res) => {
  try {
    const orderId = parseInt(req.params.orderId);
    const itemId = parseInt(req.params.itemId);

    // Delete the item
    await prisma.orderItem.delete({ where: { id: itemId } });

    // Recalculate order total
    const items = await prisma.orderItem.findMany({ where: { orderId } });
    const newTotal = items.reduce(
      (sum, item) => sum + parseFloat(item.total_price),
      0,
    );

    const updatedOrder = await prisma.order.update({
      where: { id: orderId },
      data: { total: newTotal },
      include: { items: true, user: true },
    });

    res.json({ message: "Item removed from order", order: updatedOrder });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to remove item" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server running on port ${PORT}`);
});
