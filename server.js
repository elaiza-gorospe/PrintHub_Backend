require("dotenv").config();

const express = require("express");
const prisma = require("./db/prisma");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const multer = require("multer");
const supabase = require("./db/supabase");
const { generateImage } = require("./services/falai");

const {
  generateModelFromText,
  generateModelFromImage,
} = require("./services/meshy");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: ["http://localhost:3000", "http://localhost:3001"],
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  credentials: true
}));
app.use(bodyParser.json());

// =================================================
// AI CHATBOT API (Gemini)
// =================================================
const formatMoney = (value, currency = "PHP") => {
  const amount = Number(value);
  if (!Number.isFinite(amount)) return null;
  return new Intl.NumberFormat("en-PH", {
    style: "currency",
    currency,
  }).format(amount);
};

const splitOption = (option) => {
  if (!option || typeof option !== "string") return null;
  const [label, price] = option.split("|").map((part) => part.trim());
  return price ? `${label}: ${price}` : label;
};

const formatOptions = (options = [], limit = 5) =>
  options.map(splitOption).filter(Boolean).slice(0, limit).join(", ");

const normalizeSearchText = (value = "") =>
  String(value)
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

const findProductForQuestion = (question, products) => {
  const q = normalizeSearchText(question);
  if (!q) return null;

  const aliases = [
    ["business card", "calling card", "card"],
    ["tarpaulin", "tarp", "banner"],
    ["t-shirt", "tshirt", "shirt"],
    ["sticker", "label"],
    ["notebook", "journal"],
  ];

  return products.find((product) => {
    const name = normalizeSearchText(product.name);
    const sku = normalizeSearchText(product.sku);
    const terms = [name, sku];

    aliases.forEach((group) => {
      if (group.some((term) => name.includes(normalizeSearchText(term)))) {
        terms.push(...group.map(normalizeSearchText));
      }
    });

    return terms.some((term) => term && q.includes(term));
  });
};

const buildProductSummary = (product) => {
  const basePrice = formatMoney(product.price, product.currency) || product.price;
  const quantityOptions = formatOptions(product.quantity_options);
  const shippingOptions = formatOptions(product.shipping_options);
  const sizes = formatOptions(product.size_options);
  const materials = formatOptions(product.material_options);
  const turnaround = product.turnaround_hours
    ? `${Math.ceil(product.turnaround_hours / 24)} business day(s)`
    : "varies by order";

  return [
    `${product.name} starts at ${basePrice}.`,
    product.description,
    quantityOptions ? `Quantity pricing: ${quantityOptions}.` : "",
    sizes ? `Sizes: ${sizes}.` : "",
    materials ? `Materials: ${materials}.` : "",
    `Turnaround: ${turnaround}.`,
    shippingOptions ? `Shipping: ${shippingOptions}.` : "",
    "Final pricing can change based on size, material, finish, quantity, and rush options.",
  ]
    .filter(Boolean)
    .join("\n");
};

const buildLocalChatReply = (question, products) => {
  const q = normalizeSearchText(question);
  const product = findProductForQuestion(question, products);

  if (product) return buildProductSummary(product);

  if (q.includes("product") || q.includes("service") || q.includes("offer")) {
    const names = products.map((p) => p.name).slice(0, 12).join(", ");
    return `PrintHub offers printing products and services including: ${names}. You can ask me about pricing, sizes, materials, turnaround, delivery, file requirements, or bulk orders for any of these.`;
  }

  if (q.includes("file") || q.includes("format") || q.includes("requirements")) {
    return "For print files, PrintHub accepts PDF, PNG, JPG, AI, and PSD. For best results, use high-resolution files, CMYK color when possible, and include bleed/safe margins for trimmed products.";
  }

  if (q.includes("payment") || q.includes("pay")) {
    return "PrintHub supports GCash, PayMaya, bank transfer, and card/online checkout when available.";
  }

  if (q.includes("delivery") || q.includes("shipping")) {
    return "PrintHub supports pickup and delivery options. Many products include free standard pickup/shipping options, with express delivery available for an added fee depending on the product.";
  }

  if (q.includes("bulk") || q.includes("discount")) {
    return "Bulk orders are supported. Many products already have lower per-piece pricing at higher quantities, and custom bulk quotes can be requested for larger jobs.";
  }

  return "I can help with PrintHub products, pricing, quantity options, materials, file requirements, delivery, payments, bulk orders, and order support. What product would you like to ask about?";
};

const buildCatalogContext = (products) =>
  products
    .map((product) => {
      const basePrice =
        formatMoney(product.price, product.currency) || String(product.price);
      return [
        `Product: ${product.name}`,
        `SKU: ${product.sku || "N/A"}`,
        `Description: ${product.description || "N/A"}`,
        `Base price: ${basePrice}`,
        `Print type: ${product.print_type || "N/A"}`,
        `Turnaround hours: ${product.turnaround_hours || "varies"}`,
        `Sizes: ${formatOptions(product.size_options) || "N/A"}`,
        `Materials: ${formatOptions(product.material_options) || "N/A"}`,
        `Sides: ${formatOptions(product.side_options) || "N/A"}`,
        `Finishing: ${formatOptions(product.finishing_options) || "N/A"}`,
        `Quantities: ${formatOptions(product.quantity_options, 8) || "N/A"}`,
        `Shipping: ${formatOptions(product.shipping_options) || "N/A"}`,
      ].join("\n");
    })
    .join("\n\n");

app.post("/api/chat", async (req, res) => {
  const { messages } = req.body;

  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ reply: "Invalid messages format." });
  }

  const SYSTEM_PROMPT = `You are PrintHub Assistant, a friendly and knowledgeable AI chatbot for PrintHub — a professional printing service. Help customers with:
- Pricing and quotes (business cards, flyers, posters, tarpaulins, mugs, shirts, notebooks, etc.)
- Delivery times and shipping options
- Turnaround time for orders
- Design services and file requirements (PDF, PNG, JPG, AI, PSD)
- Payment methods (GCash, PayMaya, Bank Transfer)
- Returns and refunds policy
- Bulk order discounts
- Order status and tracking
Be concise, warm, and helpful. If you don't know exact pricing, tell the customer to contact PrintHub directly for a custom quote.`;

  try {
    const products = await prisma.product.findMany({
      where: { active: true, deleted_at: null },
      orderBy: { name: "asc" },
      take: 50,
    });
    const latestUserMessage = [...messages]
      .reverse()
      .find((message) => message.role === "user")
      ?.parts?.map((part) => part.text)
      .filter(Boolean)
      .join(" ");
    const fallbackReply = buildLocalChatReply(latestUserMessage || "", products);
    const catalogPrompt = `${SYSTEM_PROMPT}

Use the product catalog below as the source of truth for PrintHub product and service questions. If the exact requested option is not listed, share the closest listed options and suggest requesting a custom quote. Do not invent prices, policies, phone numbers, or addresses.

General PrintHub service facts:
- Accepted file formats: PDF, PNG, JPG, AI, PSD.
- Payment methods: GCash, PayMaya, Bank Transfer, and card/online checkout when available.
- Bulk orders are supported and may receive custom pricing.
- Standard delivery/pickup and express options vary by product.

Product catalog:
${buildCatalogContext(products) || "No active products are currently available."}`;

    if (!process.env.GEMINI_API_KEY) {
      return res.json({ reply: fallbackReply });
    }

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          system_instruction: { parts: [{ text: catalogPrompt }] },
          contents: messages,
          generationConfig: { temperature: 0.7, maxOutputTokens: 512 },
        }),
      }
    );

    const data = await response.json();
    if (!response.ok) {
      console.error("Gemini API error:", data);
      return res.json({ reply: fallbackReply });
    }

    const reply =
      data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      fallbackReply;

    res.json({ reply });
  } catch (err) {
    console.error("Gemini API error:", err);
    res.json({
      reply:
        "I can help with PrintHub products, pricing, quantity options, file requirements, delivery, and payments. Please ask me about a product like business cards, flyers, posters, shirts, mugs, stickers, or notebooks.",
    });
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

const money = (value) =>
  new Intl.NumberFormat("en-PH", {
    style: "currency",
    currency: "PHP",
  }).format(Number(value || 0));

const getCustomerName = (order) =>
  [order.user?.first_name, order.user?.last_name].filter(Boolean).join(" ") ||
  order.user?.email ||
  "Customer";

const ORDER_STATUS_LABELS = {
  pending: "Order placed",
  confirmed: "Ordered/Paid",
  processing: "In process",
  completed: "Done",
  delivered: "Delivered",
  cancelled: "Cancelled",
  return_requested: "Return requested",
};

const PRODUCTION_STATUSES = ["confirmed", "processing", "completed"];

async function sendSystemEmail({ to, subject, text, html }) {
  const payload = {
    to,
    subject,
    body: text,
    status: transporter ? "queued" : "mock",
  };

  if (!to) return { ...payload, status: "skipped", reason: "missing recipient" };
  if (!transporter) {
    console.log(`System email mock to ${to}: ${subject}`);
    return payload;
  }

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER || process.env.GMAIL_USER,
      to,
      subject,
      text,
      html,
    });
    return { ...payload, status: "sent" };
  } catch (err) {
    console.error("System email failed:", err.message);
    return { ...payload, status: "failed", error: err.message };
  }
}

async function notifyOrderStatus(order, statusOverride) {
  const status = statusOverride || order.status || "pending";
  const label = ORDER_STATUS_LABELS[status] || status.replace(/_/g, " ");
  const customerName = getCustomerName(order);
  return sendSystemEmail({
    to: order.user?.email,
    subject: `PrintHub Order #${order.id}: ${label}`,
    text: `Hi ${customerName}, your Order #${order.id} status is now "${label}". Total: ${money(order.total)}.`,
    html: `<p>Hi ${customerName},</p><p>Your Order #${order.id} status is now <strong>${label}</strong>.</p><p>Total: <strong>${money(order.total)}</strong></p>`,
  });
}

async function notifyPaymentConfirmation(order) {
  const receipt = buildReceiptPayload(order, "paid");
  return sendSystemEmail({
    to: order.user?.email,
    subject: `Payment confirmed - PMG Receipt ${receipt.receiptNo}`,
    text: `Hi ${receipt.customerName}, payment for Order #${order.id} is confirmed. Receipt: ${receipt.receiptNo}. Total: ${money(order.total)}.`,
    html: `<p>Hi ${receipt.customerName},</p><p>Payment for Order #${order.id} is confirmed.</p><p>Receipt: <strong>${receipt.receiptNo}</strong></p><p>Total: <strong>${money(order.total)}</strong></p>`,
  });
}

async function notifyLowStockProducts(products, threshold = 10) {
  const low = products.filter((product) => Number(product.stock) <= threshold);
  if (low.length === 0) return null;
  const adminUsers = await prisma.user.findMany({
    where: { role: { in: [0, 1] }, status: "active" },
    select: { email: true },
  });
  const recipients = adminUsers.map((user) => user.email).filter(Boolean);
  if (recipients.length === 0) return null;

  return sendSystemEmail({
    to: recipients.join(","),
    subject: "PrintHub inventory alert: low stock",
    text: low
      .map((product) => `${product.name} (${product.sku || "no SKU"}): ${product.stock} left`)
      .join("\n"),
  });
}

async function notifyAdminsNewOrderForReview(order) {
  const adminUsers = await prisma.user.findMany({
    where: { role: { in: [0, 1] }, status: "active" },
    select: { email: true },
  });
  const recipients = adminUsers.map((user) => user.email).filter(Boolean);
  if (recipients.length === 0) return null;

  const customerName = getCustomerName(order);
  return sendSystemEmail({
    to: recipients.join(","),
    subject: `New order needs design approval - Order #${order.id}`,
    text: `Order #${order.id} from ${customerName} is waiting for admin design approval before payment. Total: ${money(order.total)}.`,
    html: `<p>Order #${order.id} from <strong>${customerName}</strong> is waiting for admin design approval before payment.</p><p>Total: <strong>${money(order.total)}</strong></p>`,
  });
}

async function notifyDesignApproval(order) {
  const customerName = getCustomerName(order);
  return sendSystemEmail({
    to: order.user?.email,
    subject: `PrintHub Order #${order.id}: Design approved`,
    text: `Hi ${customerName}, your design for Order #${order.id} has been approved. You can now proceed with payment.`,
    html: `<p>Hi ${customerName},</p><p>Your design for Order #${order.id} has been approved. You can now proceed with payment.</p>`,
  });
}

const otpStore = {};
let transporter = null;

// SMTP is enabled automatically when Gmail credentials are configured.
// Set SMTP_ENABLED=false in .env if you intentionally want console-only OTPs.
const SMTP_ENABLED = process.env.SMTP_ENABLED !== "false";
const EMAIL_USER = process.env.EMAIL_USER?.trim();
const EMAIL_PASS = process.env.EMAIL_PASS?.replace(/\s/g, "");

if (SMTP_ENABLED && EMAIL_USER && EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASS,
    },
  });

  transporter.verify((err, success) => {
    if (err) console.log("❌ Email transporter verify failed:", err);
    else console.log("✅ Email transporter ready:", success);
  });
} else {
  console.log(
    "SMTP disabled or missing EMAIL_USER/EMAIL_PASS. OTP will be logged to console (dev mode).",
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
          from: EMAIL_USER,
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
            from: EMAIL_USER,
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
          from: EMAIL_USER,
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
        avatar_url: u.avatar_url || "",
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
  const { name, email, birthday, gender, phone, address, avatar_url } =
    req.body;

  // Validate phone only when provided
  if (phone !== undefined && phone !== "") {
    if (!/^\+639\d{9}$/.test(phone))
      return res
        .status(400)
        .json({ message: "Phone must be +639 followed by 9 digits" });
  }

  // Validate birthday only when provided
  if (birthday) {
    const y = new Date(birthday).getFullYear();
    if (y > 2011)
      return res
        .status(400)
        .json({ message: "Only users born in 2011 or earlier allowed" });
  }

  // normalize birthday: convert valid input to ISO string, otherwise set null
  const birthdayValue = (() => {
    if (birthday === undefined || birthday === "") return undefined;
    const d = new Date(birthday);
    return isNaN(d.getTime()) ? null : d.toISOString();
  })();

  // if email is provided, validate format
  if (email !== undefined && email && !/\S+@\S+\.\S+/.test(String(email))) {
    return res
      .status(400)
      .json({ message: "Please enter a valid email address" });
  }

  // Build update data object only with provided fields
  const updateData = {};
  if (name !== undefined) {
    const parts = String(name || "").split(" ");
    updateData.first_name = parts[0] || "";
    updateData.last_name = parts.slice(1).join(" ") || "";
  }
  if (email !== undefined) updateData.email = email;
  if (birthday !== undefined) updateData.birthday = birthdayValue;
  if (gender !== undefined) updateData.gender = gender;
  if (phone !== undefined) updateData.phone = phone;
  if (address !== undefined) updateData.address = address;
  if (avatar_url !== undefined) updateData.avatar_url = avatar_url;

  try {
    // If email is being updated, ensure no duplicate exists
    if (email) {
      const dup = await prisma.user.findFirst({
        where: { email, id: { not: parseInt(req.params.id) } },
      });
      if (dup)
        return res.status(400).json({ message: "Email already registered" });
    }

    await prisma.user.update({
      where: { id: parseInt(req.params.id) },
      data: updateData,
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
          from: EMAIL_USER,
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
    // Verify products exist and have sufficient stock
    const productIds = items.map((i) => i.productId);
    const products = await prisma.product.findMany({
      where: { id: { in: productIds } },
    });

    if (products.length !== productIds.length) {
      return res
        .status(400)
        .json({ message: "One or more products not found" });
    }

    // Check stock availability for all items
    const productMap = new Map(products.map((p) => [p.id, p]));
    for (const item of items) {
      const product = productMap.get(item.productId);
      const quantity = Number(item.quantity || 1);
      if (product.stock < quantity) {
        return res.status(400).json({
          message: `Insufficient stock for ${product.name}. Available: ${product.stock}, Requested: ${quantity}`,
          productId: item.productId,
          productName: product.name,
          available: product.stock,
          requested: quantity,
        });
      }
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
        customizations: {
          ...(it.customizations || {}),
          // Preserve any imageUrl provided by frontend (AI design or product image)
          ...(it.imageUrl ? { imageUrl: it.imageUrl } : {}),
        },
      };
    });

    // Add shipping to total
    const shipping = parseFloat(shippingCost || 0);
    const total = itemsTotal + shipping;

    console.log(
      `💰 Calculation: itemsTotal=${itemsTotal}, shipping=${shipping}, total=${total}`,
    );

    // Create order and deduct stock in transaction
    const order = await prisma.$transaction(async (tx) => {
      // Create the order
      const newOrder = await tx.order.create({
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

      // Deduct stock for each item
      for (const item of items) {
        const quantity = Number(item.quantity || 1);
        await tx.product.update({
          where: { id: item.productId },
          data: { stock: { decrement: quantity } },
        });
      }

      return newOrder;
    });

    const orderWithDetails = await prisma.order.findUnique({
      where: { id: order.id },
      include: {
        user: true,
        items: { include: { product: true } },
      },
    });
    const notification = await notifyOrderStatus(orderWithDetails, "pending");
    const adminReviewNotification =
      await notifyAdminsNewOrderForReview(orderWithDetails);
    const updatedProducts = await prisma.product.findMany({
      where: { id: { in: productIds } },
    });
    const lowStockAlert = await notifyLowStockProducts(updatedProducts, 10);

    console.log(`✅ Order created: ID=${order.id}, total=${order.total}`);
    res.json({
      message: "Order created",
      order: orderWithDetails || order,
      notification,
      adminReviewNotification,
      lowStockAlert,
    });
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
      include: {
        items: {
          include: {
            product: { select: { id: true, name: true, images: true } },
          },
        },
      },
    });
    res.json(orders);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "DB error" });
  }
});

const normalizeCartCustomizations = (value) => {
  if (!value || typeof value !== "object") return {};
  return value;
};

const cartItemPayload = (item) => ({
  id: item.id,
  productId: item.productId,
  title: item.title,
  name: item.title,
  price: Number(item.price),
  qty: item.qty,
  productImage:
    item.productImage ||
    item.customizations?.imageUrl ||
    item.product?.images?.[0] ||
    null,
  images: item.product?.images || [],
  customizations: item.customizations || {},
});

// Customer cart API - shared by web and mobile clients.
app.get("/api/user/:id/cart", async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (!userId) return res.status(400).json({ message: "Invalid user id" });

  try {
    const items = await prisma.cartItem.findMany({
      where: { userId },
      include: { product: { select: { id: true, name: true, images: true } } },
      orderBy: { createdAt: "asc" },
    });
    res.json(items.map(cartItemPayload));
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to load cart" });
  }
});

app.post("/api/user/:id/cart", async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (!userId) return res.status(400).json({ message: "Invalid user id" });

  const {
    productId,
    title,
    name,
    price,
    qty = 1,
    productImage,
    images,
    customizations,
  } = req.body || {};

  if (!productId || !(title || name)) {
    return res.status(400).json({ message: "Invalid cart item" });
  }

  try {
    const normalizedCustomizations = normalizeCartCustomizations(customizations);
    const existingItems = await prisma.cartItem.findMany({
      where: { userId, productId: Number(productId) },
    });
    const match = existingItems.find(
      (item) =>
        JSON.stringify(item.customizations || {}) ===
        JSON.stringify(normalizedCustomizations),
    );

    const saved = match
      ? await prisma.cartItem.update({
          where: { id: match.id },
          data: { qty: { increment: Number(qty) || 1 } },
          include: {
            product: { select: { id: true, name: true, images: true } },
          },
        })
      : await prisma.cartItem.create({
          data: {
            userId,
            productId: Number(productId),
            title: title || name,
            price: Number(price || 0),
            qty: Math.max(1, Number(qty) || 1),
            productImage: productImage || images?.[0] || null,
            customizations: normalizedCustomizations,
          },
          include: {
            product: { select: { id: true, name: true, images: true } },
          },
        });

    res.status(match ? 200 : 201).json(cartItemPayload(saved));
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to save cart item" });
  }
});

app.patch("/api/user/:id/cart/:itemId", async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const itemId = parseInt(req.params.itemId, 10);
  const qty = Math.floor(Number(req.body?.qty || 0));

  if (!userId || !itemId) {
    return res.status(400).json({ message: "Invalid cart item" });
  }

  try {
    if (qty < 1) {
      await prisma.cartItem.deleteMany({ where: { id: itemId, userId } });
      return res.json({ message: "Cart item removed" });
    }

    const existing = await prisma.cartItem.findFirst({
      where: { id: itemId, userId },
    });

    if (!existing) {
      return res.status(404).json({ message: "Cart item not found" });
    }

    const item = await prisma.cartItem.update({
      where: { id: existing.id },
      data: { qty },
      include: { product: { select: { id: true, name: true, images: true } } },
    });

    res.json(cartItemPayload(item));
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to update cart item" });
  }
});

app.delete("/api/user/:id/cart/:itemId", async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const itemId = parseInt(req.params.itemId, 10);
  if (!userId || !itemId) return res.status(400).json({ message: "Invalid cart item" });

  try {
    await prisma.cartItem.deleteMany({ where: { id: itemId, userId } });
    res.json({ message: "Cart item removed" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to remove cart item" });
  }
});

app.delete("/api/user/:id/cart", async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (!userId) return res.status(400).json({ message: "Invalid user id" });

  try {
    await prisma.cartItem.deleteMany({ where: { userId } });
    res.json({ message: "Cart cleared" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to clear cart" });
  }
});

app.get("/api/admin/orders", async (req, res) => {
  try {
    const orders = await prisma.order.findMany({
      where: { deleted_at: null },
      include: {
        items: {
          include: {
            product: { select: { id: true, name: true, images: true } },
          },
        },
        user: true,
      },
    });
    res.json(orders);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "DB error" });
  }
});

app.get("/api/admin/production-queue", async (req, res) => {
  try {
    const orders = await prisma.order.findMany({
      where: {
        deleted_at: null,
        status: { in: PRODUCTION_STATUSES },
      },
      include: {
        user: true,
        items: { include: { product: true } },
      },
      orderBy: [{ due_date: "asc" }, { createdAt: "asc" }],
    });

    res.json({
      statuses: PRODUCTION_STATUSES,
      queue: orders.map((order) => ({
        id: order.id,
        customer: getCustomerName(order),
        status: order.status,
        statusLabel: ORDER_STATUS_LABELS[order.status] || order.status,
        payment_status: order.payment_status,
        total: order.total,
        createdAt: order.createdAt,
        due_date: order.due_date,
        items: order.items,
      })),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to fetch production queue" });
  }
});

app.get("/api/admin/reports/sales", async (req, res) => {
  try {
    const from = req.query.from ? new Date(req.query.from) : null;
    const to = req.query.to ? new Date(req.query.to) : null;
    if (to) to.setHours(23, 59, 59, 999);

    const createdAt = {};
    if (from && !isNaN(from.getTime())) createdAt.gte = from;
    if (to && !isNaN(to.getTime())) createdAt.lte = to;

    const where = {
      deleted_at: null,
      ...(Object.keys(createdAt).length ? { createdAt } : {}),
    };

    const orders = await prisma.order.findMany({
      where,
      include: {
        user: true,
        items: { include: { product: true } },
      },
      orderBy: { createdAt: "desc" },
    });

    const paidOrders = orders.filter((order) => order.payment_status === "paid");
    const completedOrders = orders.filter((order) =>
      ["completed", "delivered"].includes(order.status),
    );
    const revenue = paidOrders.reduce(
      (sum, order) => sum + Number(order.total || 0),
      0,
    );

    const byStatus = orders.reduce((acc, order) => {
      acc[order.status] = (acc[order.status] || 0) + 1;
      return acc;
    }, {});

    const productMap = new Map();
    orders.forEach((order) => {
      order.items.forEach((item) => {
        const key = item.productId;
        const current = productMap.get(key) || {
          productId: key,
          name: item.product?.name || `Product #${key}`,
          quantity: 0,
          revenue: 0,
        };
        current.quantity += Number(item.quantity || 0);
        current.revenue += Number(item.total_price || 0);
        productMap.set(key, current);
      });
    });

    res.json({
      range: {
        from: from && !isNaN(from.getTime()) ? from.toISOString() : null,
        to: to && !isNaN(to.getTime()) ? to.toISOString() : null,
      },
      summary: {
        orders: orders.length,
        paidOrders: paidOrders.length,
        completedOrders: completedOrders.length,
        revenue,
        averageOrderValue: paidOrders.length ? revenue / paidOrders.length : 0,
      },
      byStatus,
      topProducts: Array.from(productMap.values())
        .sort((a, b) => b.revenue - a.revenue)
        .slice(0, 10),
      recentOrders: orders.slice(0, 25).map((order) => ({
        id: order.id,
        customer: getCustomerName(order),
        status: order.status,
        payment_status: order.payment_status,
        total: order.total,
        createdAt: order.createdAt,
      })),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to build sales report" });
  }
});

// =================================================
// INQUIRIES API
// =================================================

// POST /api/inquiries — customer submits a quote request
app.post("/api/inquiries", async (req, res) => {
  const {
    userId,
    product_title,
    subject,
    name,
    email,
    quantity,
    size,
    color,
    material,
    finishing,
    printing,
    processing,
    delivery,
    other,
  } = req.body;

  if (!subject || !name || !email) {
    return res
      .status(400)
      .json({ message: "Subject, name, and email are required" });
  }

  try {
    const inquiry = await prisma.inquiry.create({
      data: {
        userId: userId ? parseInt(userId) : null,
        product_title,
        subject,
        name,
        email,
        quantity,
        size,
        color,
        material,
        finishing,
        printing,
        processing,
        delivery,
        other,
        status: "new",
      },
    });
    res.status(201).json({ message: "Inquiry submitted", inquiry });
  } catch (e) {
    console.error("Inquiry creation failed:", e);
    res.status(500).json({ message: "Failed to submit inquiry" });
  }
});

// GET /api/inquiries — admin: list all inquiries (optionally filter by status)
app.get("/api/inquiries", async (req, res) => {
  const { status } = req.query;
  try {
    const inquiries = await prisma.inquiry.findMany({
      where: status ? { status } : {},
      include: {
        user: {
          select: { id: true, first_name: true, last_name: true, email: true },
        },
      },
      orderBy: { createdAt: "desc" },
    });
    res.json(inquiries);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to fetch inquiries" });
  }
});

// GET /api/inquiries/:id — admin: single inquiry detail
app.get("/api/inquiries/:id", async (req, res) => {
  try {
    const inquiry = await prisma.inquiry.findUnique({
      where: { id: parseInt(req.params.id) },
      include: {
        user: {
          select: { id: true, first_name: true, last_name: true, email: true },
        },
      },
    });
    if (!inquiry) return res.status(404).json({ message: "Inquiry not found" });
    res.json(inquiry);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to fetch inquiry" });
  }
});

// PUT /api/inquiries/:id — admin: update status / quoted_price / admin_notes
app.put("/api/inquiries/:id", async (req, res) => {
  const { status, quoted_price, admin_notes } = req.body;
  const inquiryId = parseInt(req.params.id);
  try {
    // Fetch current state to detect first-time quoted_price set
    const existing = await prisma.inquiry.findUnique({
      where: { id: inquiryId },
    });
    if (!existing)
      return res.status(404).json({ message: "Inquiry not found" });

    const newPrice =
      quoted_price !== undefined
        ? quoted_price
          ? parseFloat(quoted_price)
          : null
        : undefined;

    // Auto-create order only when: price first set, no order yet, AND current status is "new"
    let orderId = existing.order_id;
    if (newPrice && !existing.order_id && existing.status === "new") {
      const summary = [
        existing.product_title && `Product: ${existing.product_title}`,
        existing.quantity && `Qty: ${existing.quantity}`,
        existing.size && `Size: ${existing.size}`,
        existing.color && `Color: ${existing.color}`,
        existing.material && `Material: ${existing.material}`,
        existing.finishing && `Finishing: ${existing.finishing}`,
        existing.printing && `Printing: ${existing.printing}`,
        existing.processing && `Processing: ${existing.processing}`,
        existing.delivery && `Delivery: ${existing.delivery}`,
        existing.other && `Other: ${existing.other}`,
      ]
        .filter(Boolean)
        .join(" | ");

      // Find or create a generic "Custom Inquiry" product
      let inquiryProduct = await prisma.product.findFirst({
        where: { sku: "INQUIRY-CUSTOM" },
      });
      if (!inquiryProduct) {
        inquiryProduct = await prisma.product.create({
          data: {
            name: "Custom Inquiry Order",
            sku: "INQUIRY-CUSTOM",
            description: "Generic product for custom inquiry orders",
            price: "0.00",
            stock: 999,
            active: true,
          },
        });
      }

      const order = await prisma.order.create({
        data: {
          userId: existing.userId || null,
          total: newPrice,
          currency: "PHP",
          status: "pending",
          payment_status: "awaiting_payment",
          shipping_address: summary || "Custom inquiry order",
          billing_address: `Inquiry #${inquiryId} — ${existing.name} <${existing.email}>`,
          items: {
            create: {
              productId: inquiryProduct.id,
              quantity: parseInt(existing.quantity) || 1,
              unit_price: newPrice,
              total_price: newPrice * (parseInt(existing.quantity) || 1),
              customizations: {
                inquiry_id: existing.id,
                product_title: existing.product_title,
                subject: existing.subject,
                customer_name: existing.name,
                customer_email: existing.email,
                size: existing.size,
                color: existing.color,
                material: existing.material,
                finishing: existing.finishing,
                printing: existing.printing,
                processing: existing.processing,
                delivery: existing.delivery,
                other: existing.other,
              },
            },
          },
        },
      });
      orderId = order.id;
    }

    const inquiry = await prisma.inquiry.update({
      where: { id: inquiryId },
      data: {
        // Auto-set to "converted" when price is first set on a "new" inquiry, unless admin passed explicit status
        status:
          status ||
          (newPrice && !existing.order_id && existing.status === "new"
            ? "converted"
            : undefined) ||
          existing.status,
        ...(newPrice !== undefined && { quoted_price: newPrice }),
        ...(admin_notes !== undefined && { admin_notes }),
        ...(orderId && !existing.order_id && { order_id: orderId }),
      },
    });
    res.json({ message: "Inquiry updated", inquiry });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025")
      return res.status(404).json({ message: "Inquiry not found" });
    res.status(500).json({ message: "Failed to update inquiry" });
  }
});

// GET /api/user/:id/inquiries — customer: own inquiries
app.get("/api/user/:id/inquiries", async (req, res) => {
  const userId = parseInt(req.params.id);
  try {
    const inquiries = await prisma.inquiry.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
    });
    res.json(inquiries);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to fetch inquiries" });
  }
});

// PUT /api/inquiries/:id/convert — admin: convert accepted inquiry to an order
app.put("/api/inquiries/:id/convert", async (req, res) => {
  const inquiryId = parseInt(req.params.id);
  try {
    const inquiry = await prisma.inquiry.findUnique({
      where: { id: inquiryId },
    });
    if (!inquiry) return res.status(404).json({ message: "Inquiry not found" });
    if (!inquiry.quoted_price)
      return res.status(400).json({ message: "Inquiry has no quoted price" });
    if (inquiry.status === "converted")
      return res.status(400).json({ message: "Inquiry already converted" });

    // Build a summary of what was quoted for the order notes
    const summary = [
      inquiry.product_title && `Product: ${inquiry.product_title}`,
      inquiry.quantity && `Qty: ${inquiry.quantity}`,
      inquiry.size && `Size: ${inquiry.size}`,
      inquiry.color && `Color: ${inquiry.color}`,
      inquiry.material && `Material: ${inquiry.material}`,
      inquiry.finishing && `Finishing: ${inquiry.finishing}`,
      inquiry.printing && `Printing: ${inquiry.printing}`,
      inquiry.processing && `Processing: ${inquiry.processing}`,
      inquiry.delivery && `Delivery: ${inquiry.delivery}`,
      inquiry.other && `Other: ${inquiry.other}`,
    ]
      .filter(Boolean)
      .join(" | ");

    const [order] = await prisma.$transaction([
      prisma.order.create({
        data: {
          userId: inquiry.userId || null,
          total: inquiry.quoted_price,
          currency: "PHP",
          status: "pending",
          payment_status: "awaiting_payment",
          shipping_address: summary || "Custom inquiry order",
          billing_address: `Inquiry #${inquiry.id} — ${inquiry.name} <${inquiry.email}>`,
        },
      }),
      prisma.inquiry.update({
        where: { id: inquiryId },
        data: { status: "converted" },
      }),
    ]);

    res.json({
      message: "Inquiry converted to order",
      orderId: order.id,
      order,
    });
  } catch (e) {
    console.error("Inquiry convert failed:", e);
    res.status(500).json({ message: "Failed to convert inquiry" });
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

// GET low-stock products (admin dashboard)
app.get("/api/admin/low-stock", async (req, res) => {
  try {
    const threshold = parseInt(req.query.threshold) || 10;
    const limit = parseInt(req.query.limit) || 10;
    const page = parseInt(req.query.page) || 1;
    const skip = (page - 1) * limit;

    const products = await prisma.product.findMany({
      where: {
        active: true,
        deleted_at: null,
        stock: { lte: threshold },
      },
      orderBy: { stock: "asc" },
      skip,
      take: limit,
    });

    const total = await prisma.product.count({
      where: { active: true, deleted_at: null, stock: { lte: threshold } },
    });

    res.json({
      products,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to fetch low-stock products" });
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
      color_options,
      size_options,
      material_options,
      side_options,
      finishing_options,
      processing_options,
      delivery_options,
      quantity_options,
      shipping_options,
      quantity_mode,
      quantity_count,
      print_type,
      turnaround_hours,
      ai_prompt_rules,
      print_zones,
      category,
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
        colorOptions: colorOptions || color_options || [],
        color_options: color_options || colorOptions || [],
        size_options: size_options || [],
        material_options: material_options || [],
        side_options: side_options || [],
        finishing_options: finishing_options || [],
        processing_options: processing_options || [],
        delivery_options: delivery_options || [],
        quantity_options: quantity_options || [],
        ...(quantity_mode !== undefined && { quantity_mode }),
        ...(quantity_count !== undefined && {
          quantity_count:
            quantity_count === null ? null : parseInt(quantity_count),
        }),
        shipping_options: shipping_options || [],
        print_type,
        turnaround_hours: turnaround_hours ? parseInt(turnaround_hours) : null,
        ai_prompt_rules: ai_prompt_rules || null,
        print_zones: print_zones || [],
        category: category || "other",
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
      color_options,
      size_options,
      material_options,
      side_options,
      finishing_options,
      processing_options,
      delivery_options,
      quantity_options,
      shipping_options,
      print_type,
      turnaround_hours,
      ai_prompt_rules,
      print_zones,
      category,
      images,
      active,
      sku,
      quantity_mode,
      quantity_count,
    } = req.body;

    const product = await prisma.product.update({
      where: { id: parseInt(req.params.id) },
      data: {
        ...(name && { name }),
        ...(sku !== undefined && { sku }),
        ...(description !== undefined && { description }),
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
        ...(material !== undefined && { material }),
        ...(colorOptions !== undefined && { colorOptions }),
        ...(color_options !== undefined && { color_options }),
        ...(size_options !== undefined && { size_options }),
        ...(material_options !== undefined && { material_options }),
        ...(side_options !== undefined && { side_options }),
        ...(finishing_options !== undefined && { finishing_options }),
        ...(processing_options !== undefined && { processing_options }),
        ...(delivery_options !== undefined && { delivery_options }),
        ...(quantity_options !== undefined && { quantity_options }),
        ...(quantity_mode !== undefined && { quantity_mode }),
        ...(quantity_count !== undefined && {
          quantity_count:
            quantity_count === null ? null : parseInt(quantity_count),
        }),
        ...(shipping_options !== undefined && { shipping_options }),
        ...(print_type && { print_type }),
        ...(turnaround_hours !== undefined && {
          turnaround_hours: turnaround_hours
            ? parseInt(turnaround_hours)
            : null,
        }),
        ...(images !== undefined && { images }),
        ...(ai_prompt_rules !== undefined && { ai_prompt_rules }),
        ...(print_zones !== undefined && { print_zones }),
        ...(category !== undefined && { category }),
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

// POST /api/products/:id/add-stock — increment stock atomically and optionally update quantity_options
app.post("/api/products/:id/add-stock", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { add, quantity_options } = req.body;

    const inc = parseInt(add);
    if (!inc || isNaN(inc) || inc <= 0)
      return res.status(400).json({ message: "Invalid add amount" });

    const updateData = {
      stock: { increment: inc },
    };
    if (quantity_options !== undefined)
      updateData.quantity_options = quantity_options;

    const product = await prisma.product.update({
      where: { id },
      data: updateData,
    });

    res.json({ message: "Stock updated", product });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025")
      return res.status(404).json({ message: "Product not found" });
    res.status(500).json({ message: "Failed to add stock" });
  }
});

// UPLOAD product image
const PRODUCT_MAX_UPLOAD_SIZE = 3 * 1024 * 1024; // 3 MB
const productUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: PRODUCT_MAX_UPLOAD_SIZE },
  fileFilter: (_req, file, cb) => {
    const allowed = new Set([
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif",
    ]);
    if (allowed.has(file.mimetype)) cb(null, true);
    else cb(new Error("Only JPEG, PNG, WebP, and GIF images are allowed"));
  },
});

app.post(
  "/api/products/upload",
  productUpload.single("file"),
  async (req, res) => {
    if (!req.file) return res.status(400).json({ message: "No file provided" });

    try {
      const { data: existing } =
        await supabase.storage.getBucket("printhub_s3");
      if (!existing) {
        const { error: bucketErr } = await supabase.storage.createBucket(
          "printhub_s3",
          {
            public: true,
            fileSizeLimit: PRODUCT_MAX_UPLOAD_SIZE,
          },
        );
        if (bucketErr)
          throw new Error(`Cannot create storage bucket: ${bucketErr.message}`);
      }

      const ext = req.file.mimetype.split("/")[1] || "jpg";
      const path = `products/${Date.now()}.${ext}`;

      const { error } = await supabase.storage
        .from("printhub_s3")
        .upload(path, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false,
        });

      if (error) throw new Error(`Storage upload failed: ${error.message}`);

      const { data: urlData } = supabase.storage
        .from("printhub_s3")
        .getPublicUrl(path);

      return res.status(201).json({
        url: urlData.publicUrl,
        path,
        size: req.file.size,
        mimeType: req.file.mimetype,
      });
    } catch (e) {
      console.error("Product upload error:", e.message);
      return res.status(500).json({ message: e.message || "Upload failed" });
    }
  },
);

// Multer error handler for product upload
app.use((err, req, res, next) => {
  if (
    err instanceof multer.MulterError &&
    req.path === "/api/products/upload"
  ) {
    return res.status(400).json({ message: err.message });
  }
  if (err && req.path === "/api/products/upload") {
    return res.status(400).json({ message: err.message });
  }
  next(err);
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
        ...(status === "delivered" && { delivered_at: new Date() }),
        ...(proofApproved !== undefined && { proofApproved }),
        ...(due_date && { due_date: new Date(due_date) }),
        ...(shipping_address && { shipping_address }),
        ...(billing_address && { billing_address }),
      },
      include: { items: true, user: true },
    });

    const notification = status ? await notifyOrderStatus(order, status) : null;
    res.json({ message: "Order updated", order, notification });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025") {
      return res.status(404).json({ message: "Order not found" });
    }
    res.status(500).json({ message: "Failed to update order" });
  }
});

app.post("/api/orders/:id/onsite-payment", async (req, res) => {
  try {
    const { payment_reference } = req.body || {};
    const existing = await prisma.order.findUnique({
      where: { id: parseInt(req.params.id) },
      select: { id: true, proofApproved: true, deleted_at: true },
    });
    if (!existing || existing.deleted_at) {
      return res.status(404).json({ message: "Order not found" });
    }
    if (!existing.proofApproved) {
      return res.status(403).json({
        message:
          "Design approval is required before recording payment for this order.",
      });
    }

    const order = await prisma.order.update({
      where: { id: parseInt(req.params.id) },
      data: {
        payment_status: "paid",
        status: "confirmed",
        payment_method: "onsite",
        payment_reference:
          payment_reference || `ONSITE-${Date.now()}-${req.params.id}`,
      },
      include: {
        user: true,
        items: { include: { product: true } },
      },
    });
    const paymentNotification = await notifyPaymentConfirmation(order);
    const statusNotification = await notifyOrderStatus(order, "confirmed");

    res.json({
      message: "Order marked as paid onsite",
      order,
      receipt: buildReceiptPayload(order, "paid"),
      notifications: [paymentNotification, statusNotification],
    });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025") {
      return res.status(404).json({ message: "Order not found" });
    }
    res.status(500).json({ message: "Failed to record onsite payment" });
  }
});

app.post("/api/orders/:id/approve-design", async (req, res) => {
  try {
    const order = await prisma.order.update({
      where: { id: parseInt(req.params.id) },
      data: { proofApproved: true },
      include: {
        user: true,
        items: { include: { product: true } },
      },
    });
    const notification = await notifyDesignApproval(order);
    res.json({
      message: "Design approved. Customer can now pay.",
      order,
      notification,
    });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025") {
      return res.status(404).json({ message: "Order not found" });
    }
    res.status(500).json({ message: "Failed to approve design" });
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

    const notification = await notifyOrderStatus(order, "delivered");
    res.json({ message: "Order marked as delivered", order, notification });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025") {
      return res.status(404).json({ message: "Order not found" });
    }
    res.status(500).json({ message: "Failed to deliver order" });
  }
});

// DELETE order (soft delete) - restore stock
app.delete("/api/orders/:id", async (req, res) => {
  try {
    const orderId = parseInt(req.params.id);

    // Fetch order with items before deletion
    const orderToDelete = await prisma.order.findUnique({
      where: { id: orderId },
      include: { items: true },
    });

    if (!orderToDelete) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Restore stock and delete order in transaction
    const order = await prisma.$transaction(async (tx) => {
      // Restore stock for all items
      for (const item of orderToDelete.items) {
        await tx.product.update({
          where: { id: item.productId },
          data: { stock: { increment: item.quantity } },
        });
      }

      // Soft delete the order
      return await tx.order.update({
        where: { id: orderId },
        data: { deleted_at: new Date() },
        include: { items: true, user: true },
      });
    });

    console.log(`✅ Order ${orderId} deleted and stock restored`);
    res.json({ message: "Order deleted and stock restored", order });
  } catch (e) {
    console.error(e);
    if (e.code === "P2025") {
      return res.status(404).json({ message: "Order not found" });
    }
    res.status(500).json({ message: "Failed to delete order" });
  }
});

// DELETE order item - restore stock for that product
app.delete("/api/orders/:orderId/items/:itemId", async (req, res) => {
  try {
    const orderId = parseInt(req.params.orderId);
    const itemId = parseInt(req.params.itemId);

    // Fetch item before deletion
    const itemToDelete = await prisma.orderItem.findUnique({
      where: { id: itemId },
    });

    if (!itemToDelete) {
      return res.status(404).json({ message: "Order item not found" });
    }

    // Delete item and restore stock in transaction
    const updatedOrder = await prisma.$transaction(async (tx) => {
      // Restore stock
      await tx.product.update({
        where: { id: itemToDelete.productId },
        data: { stock: { increment: itemToDelete.quantity } },
      });

      // Delete the item
      await tx.orderItem.delete({ where: { id: itemId } });

      // Recalculate order total
      const items = await tx.orderItem.findMany({ where: { orderId } });
      const newTotal = items.reduce(
        (sum, item) => sum + parseFloat(item.total_price),
        0,
      );

      return await tx.order.update({
        where: { id: orderId },
        data: { total: newTotal },
        include: { items: true, user: true },
      });
    });

    console.log(`✅ Item ${itemId} removed and stock restored`);
    res.json({
      message: "Item removed from order and stock restored",
      order: updatedOrder,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to remove item" });
  }
});

// =================================================
// AI BUILDER API
// =================================================
const BUILDER_BUCKET = "printhub_s3";
const MAX_UPLOAD_SIZE = 10 * 1024 * 1024; // 10 MB
const ALLOWED_MIME = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
]);
const GENERATION_COOLDOWN_MS = 30_000; // 30 s per user
const generationCooldown = {}; // ownerKey -> lastGeneratedAt (ms)

// Multer: memory storage, size + type guard
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_SIZE },
  fileFilter: (_req, file, cb) => {
    if (ALLOWED_MIME.has(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only JPEG, PNG, WebP, and GIF images are allowed"));
    }
  },
});

/** Ensure the storage bucket exists and is public */
async function ensureBucket() {
  const { data: existing } = await supabase.storage.getBucket(BUILDER_BUCKET);
  if (!existing) {
    const { error } = await supabase.storage.createBucket(BUILDER_BUCKET, {
      public: true,
      fileSizeLimit: MAX_UPLOAD_SIZE,
    });
    if (error)
      throw new Error(`Cannot create storage bucket: ${error.message}`);
  } else if (!existing.public) {
    // Bucket exists but is private — make it public
    const { error } = await supabase.storage.updateBucket(BUILDER_BUCKET, {
      public: true,
    });
    if (error)
      throw new Error(`Cannot update bucket visibility: ${error.message}`);
  }
}

/** Extract userId from X-User-Id header; returns null when missing/invalid */
function getUserId(req) {
  const raw = req.headers["x-user-id"];
  if (!raw) return null;
  const id = parseInt(raw, 10);
  return Number.isFinite(id) && id > 0 ? id : null;
}

// POST /api/builder/upload — upload a source asset to Supabase storage
app.post("/api/builder/upload", upload.single("file"), async (req, res) => {
  const userId = getUserId(req);
  if (!userId)
    return res
      .status(401)
      .json({ message: "Authentication required: send X-User-Id header" });

  if (!req.file) return res.status(400).json({ message: "No file provided" });

  try {
    await ensureBucket();

    const { description } = req.body;
    const ext = req.file.mimetype.split("/")[1] || "jpg";
    const path = `uploads/${userId}/${Date.now()}.${ext}`;

    if (description) {
      console.log(
        `📤 Builder upload: userId=${userId}, description="${description.slice(0, 80)}..."`,
      );
    } else {
      console.log(`📤 Builder upload: userId=${userId}`);
    }

    const { error } = await supabase.storage
      .from(BUILDER_BUCKET)
      .upload(path, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false,
      });

    if (error) throw new Error(`Storage upload failed: ${error.message}`);

    const { data: urlData } = supabase.storage
      .from(BUILDER_BUCKET)
      .getPublicUrl(path);

    return res.status(201).json({
      url: urlData.publicUrl,
      path,
      size: req.file.size,
      mimeType: req.file.mimetype,
    });
  } catch (e) {
    console.error("Builder upload error:", e.message);
    return res.status(500).json({ message: e.message || "Upload failed" });
  }
});

// Avatar upload (2 MB)
const AVATAR_MAX_UPLOAD_SIZE = 2 * 1024 * 1024; // 2 MB
const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: AVATAR_MAX_UPLOAD_SIZE },
  fileFilter: (_req, file, cb) => {
    if (ALLOWED_MIME.has(file.mimetype)) cb(null, true);
    else cb(new Error("Only JPEG, PNG, WebP, and GIF images are allowed"));
  },
});

app.post(
  "/api/user/avatar-upload",
  avatarUpload.single("file"),
  async (req, res) => {
    const userId = getUserId(req);
    if (!userId)
      return res
        .status(401)
        .json({ message: "Authentication required: send X-User-Id header" });

    if (!req.file) return res.status(400).json({ message: "No file provided" });

    try {
      await ensureBucket();

      const ext = req.file.mimetype.split("/")[1] || "jpg";
      const path = `avatars/${userId}/${Date.now()}.${ext}`;

      const { error } = await supabase.storage
        .from(BUILDER_BUCKET)
        .upload(path, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false,
        });

      if (error) throw new Error(`Storage upload failed: ${error.message}`);

      const { data: urlData } = supabase.storage
        .from(BUILDER_BUCKET)
        .getPublicUrl(path);

      return res.status(201).json({
        url: urlData.publicUrl,
        path,
        size: req.file.size,
        mimeType: req.file.mimetype,
      });
    } catch (e) {
      console.error("Avatar upload error:", e.message);
      return res.status(500).json({ message: e.message || "Upload failed" });
    }
  },
);

// Multer error handler for builder and avatar upload
app.use((err, req, res, next) => {
  if (
    err instanceof multer.MulterError ||
    (err &&
      ALLOWED_MIME !== undefined &&
      (req.path === "/api/builder/upload" ||
        req.path === "/api/user/avatar-upload"))
  ) {
    return res.status(400).json({ message: err.message });
  }
  next(err);
});

// POST /api/builder/generate-image — generate a 2D design image via fal.ai and store in Supabase
app.post("/api/builder/generate-image", async (req, res) => {
  const userId = getUserId(req);
  const rawOwner = userId
    ? String(userId)
    : req.headers["x-forwarded-for"] || req.ip || "guest";
  const ownerKey = String(rawOwner).replace(/[^a-zA-Z0-9_-]/g, "_");

  const { prompt, imageSize } = req.body;
  if (!prompt || typeof prompt !== "string" || prompt.trim().length === 0)
    return res.status(400).json({ message: "prompt is required" });
  if (prompt.trim().length > 2000)
    return res
      .status(400)
      .json({ message: "prompt must be 2000 characters or fewer" });

  // Per-user cooldown (shared with 3D generation)
  const now = Date.now();
  const last = generationCooldown[ownerKey] || 0;
  const remaining = GENERATION_COOLDOWN_MS - (now - last);
  if (remaining > 0) {
    return res.status(429).json({
      message: `Please wait ${Math.ceil(remaining / 1000)} seconds before generating again`,
      retryAfterMs: remaining,
    });
  }
  generationCooldown[ownerKey] = now;

  try {
    console.log(
      `🎨 Builder generate-image (2D): owner=${ownerKey}${userId ? ` (userId=${userId})` : " (guest)"}, prompt="${prompt.slice(0, 80)}..."`,
    );

    const result = await generateImage({
      prompt: prompt.trim(),
      imageSize: imageSize || "square_hd",
    });

    // Upload to Supabase so URL is stable (Pollinations URLs are ephemeral)
    await ensureBucket();
    let imageUrl = result.url;
    let stored = false;
    let storagePath = null;

    try {
      const imgRes = await fetch(result.url);
      if (imgRes.ok) {
        const imgBuffer = Buffer.from(await imgRes.arrayBuffer());
        const ext = result.url.includes(".png") ? "png" : "jpg";
        storagePath = `generated-images/${ownerKey}/${Date.now()}.${ext}`;
        const { error: storageErr } = await supabase.storage
          .from(BUILDER_BUCKET)
          .upload(storagePath, imgBuffer, {
            contentType: ext === "png" ? "image/png" : "image/jpeg",
            upsert: false,
          });
        if (!storageErr) {
          const { data: urlData } = supabase.storage
            .from(BUILDER_BUCKET)
            .getPublicUrl(storagePath);
          imageUrl = urlData.publicUrl;
          stored = true;
        }
      }
    } catch (uploadErr) {
      console.warn("Supabase upload failed (non-fatal):", uploadErr.message);
    }

    console.log(
      `✅ Generated 2D image${stored ? " + stored: " + storagePath : " (Supabase skipped)"}`,
    );
    return res.json({
      imageUrl,
      width: result.width,
      height: result.height,
      prompt: prompt.trim(),
      stored,
      path: storagePath,
    });
  } catch (e) {
    delete generationCooldown[ownerKey];
    console.error("Builder generate-image error:", e.message);
    return res
      .status(500)
      .json({ message: e.message || "Image generation failed" });
  }
});

// POST /api/builder/generate — generate a 3D model via Meshy and store in Supabase
app.post("/api/builder/generate", async (req, res) => {
  const userId = getUserId(req);
  // allow guests: derive an ownerKey for cooldown/storage (prefer userId when present)
  const rawOwner = userId
    ? String(userId)
    : req.headers["x-forwarded-for"] || req.ip || "guest";
  // sanitize owner key for use in storage paths and map keys
  const ownerKey = String(rawOwner).replace(/[^a-zA-Z0-9_-]/g, "_");

  const { prompt, quality, productId } = req.body;
  if (!prompt || typeof prompt !== "string" || prompt.trim().length === 0)
    return res.status(400).json({ message: "prompt is required" });

  if (prompt.trim().length > 2000)
    return res
      .status(400)
      .json({ message: "prompt must be 2000 characters or fewer" });

  // Per-user cooldown
  const now = Date.now();
  const last = generationCooldown[ownerKey] || 0;
  const remaining = GENERATION_COOLDOWN_MS - (now - last);
  if (remaining > 0) {
    return res.status(429).json({
      message: `Please wait ${Math.ceil(remaining / 1000)} seconds before generating again`,
      retryAfterMs: remaining,
    });
  }

  generationCooldown[ownerKey] = now;

  try {
    console.log(
      `🎨 Builder generate (3D): owner=${ownerKey}${userId ? ` (userId=${userId})` : " (guest)"}, productId=${productId || "N/A"}, prompt="${prompt.slice(0, 80)}..."`,
    );

    // Call Meshy text-to-3D
    const { glbUrl, meshyTaskId } = await generateModelFromText({
      prompt: prompt.trim(),
      quality: quality || "standard",
    });

    // Download generated GLB and persist in Supabase
    await ensureBucket();

    console.log(`⬇️  Fetching generated GLB from Meshy…`);
    const glbRes = await fetch(glbUrl);
    if (!glbRes.ok)
      throw new Error(
        `Failed to fetch generated GLB from Meshy (${glbRes.status})`,
      );
    const glbBuffer = Buffer.from(await glbRes.arrayBuffer());

    const storagePath = `generated-models/${ownerKey}/${Date.now()}.glb`;
    const { error: storageErr } = await supabase.storage
      .from(BUILDER_BUCKET)
      .upload(storagePath, glbBuffer, {
        contentType: "model/gltf-binary",
        upsert: false,
      });

    if (storageErr) {
      // Non-fatal: return the Meshy URL directly if Supabase storage fails
      console.warn(
        "Storage persist failed, returning Meshy URL:",
        storageErr.message,
      );
      return res.json({
        glbUrl,
        meshyTaskId,
        stored: false,
      });
    }

    const { data: urlData } = supabase.storage
      .from(BUILDER_BUCKET)
      .getPublicUrl(storagePath);

    console.log(`✅ Generated 3D model + stored: ${storagePath}`);
    return res.json({
      glbUrl: urlData.publicUrl,
      meshyUrl: glbUrl,
      meshyTaskId,
      stored: true,
      path: storagePath,
    });
  } catch (e) {
    // Reset cooldown on failure so user can retry
    delete generationCooldown[ownerKey];
    console.error("Builder generate (3D) error:", e.message);
    return res
      .status(500)
      .json({ message: e.message || "3D generation failed" });
  }
});

// POST /api/builder/generate-from-image — generate a 3D model from uploaded image via Meshy
app.post("/api/builder/generate-from-image", async (req, res) => {
  const userId = getUserId(req);
  const rawOwner = userId
    ? String(userId)
    : req.headers["x-forwarded-for"] || req.ip || "guest";
  const ownerKey = String(rawOwner).replace(/[^a-zA-Z0-9_-]/g, "_");

  const { imageUrl, description, quality } = req.body;
  if (
    !imageUrl ||
    typeof imageUrl !== "string" ||
    imageUrl.trim().length === 0
  ) {
    return res.status(400).json({ message: "imageUrl is required" });
  }

  // Per-user cooldown
  const now = Date.now();
  const last = generationCooldown[ownerKey] || 0;
  const remaining = GENERATION_COOLDOWN_MS - (now - last);
  if (remaining > 0) {
    return res.status(429).json({
      message: `Please wait ${Math.ceil(remaining / 1000)} seconds before generating again`,
      retryAfterMs: remaining,
    });
  }

  generationCooldown[ownerKey] = now;

  try {
    console.log(
      `🎨 Builder generate-from-image: owner=${ownerKey}${userId ? ` (userId=${userId})` : " (guest)"}, image=${imageUrl.slice(0, 60)}...${description ? ` description="${description.slice(0, 60)}..."` : ""}`,
    );

    // Call Meshy image-to-3D
    const { glbUrl, meshyTaskId } = await generateModelFromImage({
      imageUrl: imageUrl.trim(),
      description: description ? description.trim() : undefined,
      quality: quality || "standard",
    });

    // Download generated GLB and persist in Supabase
    await ensureBucket();

    console.log(`⬇️  Fetching generated GLB from Meshy…`);
    const glbRes = await fetch(glbUrl);
    if (!glbRes.ok)
      throw new Error(
        `Failed to fetch generated GLB from Meshy (${glbRes.status})`,
      );
    const glbBuffer = Buffer.from(await glbRes.arrayBuffer());

    const storagePath = `generated-models/${ownerKey}/${Date.now()}.glb`;
    const { error: storageErr } = await supabase.storage
      .from(BUILDER_BUCKET)
      .upload(storagePath, glbBuffer, {
        contentType: "model/gltf-binary",
        upsert: false,
      });

    if (storageErr) {
      console.warn(
        "Storage persist failed, returning Meshy URL:",
        storageErr.message,
      );
      return res.json({
        glbUrl,
        meshyTaskId,
        stored: false,
      });
    }

    const { data: urlData } = supabase.storage
      .from(BUILDER_BUCKET)
      .getPublicUrl(storagePath);

    console.log(`✅ Generated 3D model from image + stored: ${storagePath}`);
    return res.json({
      glbUrl: urlData.publicUrl,
      meshyUrl: glbUrl,
      meshyTaskId,
      stored: true,
      path: storagePath,
    });
  } catch (e) {
    delete generationCooldown[ownerKey];
    console.error("Builder generate-from-image error:", e.message);
    return res
      .status(500)
      .json({ message: e.message || "3D generation from image failed" });
  }
});

// POST /api/builder/generate-3d — wrap design image as texture on 3D object
app.post("/api/builder/generate-3d", async (req, res) => {
  const userId = getUserId(req);
  const { prompt, designImageUrl } = req.body;

  if (!prompt || typeof prompt !== "string" || prompt.trim().length === 0) {
    return res.status(400).json({ message: "prompt is required" });
  }

  if (!designImageUrl) {
    return res.status(400).json({ message: "designImageUrl is required" });
  }

  try {
    console.log(
      `🎭 Builder generate-3d: userId=${userId || "guest"}, prompt="${prompt.slice(0, 80)}..."`,
    );

    // Return design image wrapped as a 3D textured object
    // Frontend will create a 3D scene with this image as a texture on a cube
    return res.json({
      message: "3D scene ready",
      type: "textured-cube",
      textureUrl: designImageUrl,
      prompt: prompt.trim(),
    });
  } catch (e) {
    console.error("Builder generate-3d error:", e.message);
    return res.status(500).json({
      message: e.message || "3D generation failed",
    });
  }
});

// =================================================
// PAYMONGO PAYMENT API
// =================================================

const PAYMONGO_BASE = "https://api.paymongo.com/v1";

function buildReceiptPayload(order, statusOverride) {
  const paymentStatus = statusOverride || order.payment_status || "unpaid";
  const isPaid = paymentStatus === "paid";
  const customerName =
    [order.user?.first_name, order.user?.last_name].filter(Boolean).join(" ") ||
    order.user?.email ||
    "Customer";
  const customerEmail = order.user?.email || "";
  const receiptNo = `PMG-${String(order.id).padStart(6, "0")}`;
  const paidAt =
    isPaid && order.updatedAt ? new Date(order.updatedAt).toISOString() : null;

  return {
    receiptNo,
    orderId: order.id,
    customerName,
    customerEmail,
    status: paymentStatus,
    paymentStatus,
    paymentMethod: order.payment_method || "Online payment",
    paymentReference: order.payment_reference || order.paymongo_session_id || "",
    total: order.total,
    currency: order.currency || "PHP",
    issuedAt: paidAt || new Date().toISOString(),
    paidAt,
    items: (order.items || []).map((item) => ({
      id: item.id,
      productName: item.product?.name || `Product #${item.productId}`,
      quantity: item.quantity,
      unitPrice: item.unit_price,
      totalPrice: item.total_price,
    })),
    mockEmail: {
      to: customerEmail,
      subject: isPaid
        ? `Payment successful - PMG Receipt ${receiptNo}`
        : `Payment update - PMG Order #${order.id}`,
      status: isPaid ? "success" : "not_paid",
      body: isPaid
        ? `Hi ${customerName}, your payment for Order #${order.id} was successful. Your e-receipt number is ${receiptNo}.`
        : `Hi ${customerName}, payment for Order #${order.id} is not yet confirmed. You can retry payment from My Orders.`,
    },
  };
}

function paymongoAuth() {
  const key = process.env.PAYMONGO_SECRET_KEY;
  if (!key) {
    console.warn(
      "⚠️ PAYMONGO_SECRET_KEY not set. PayMongo requests will fail until configured.",
    );
    return "";
  }
  return Buffer.from(key + ":").toString("base64");
}

function paymongoPaymentMethods(requestedMethods) {
  const source = Array.isArray(requestedMethods)
    ? requestedMethods.join(",")
    : process.env.PAYMONGO_PAYMENT_METHOD_TYPES;
  const configured = process.env.PAYMONGO_PAYMENT_METHOD_TYPES;
  const methods = (source || configured || "qrph")
    .split(",")
    .map((method) => method.trim().toLowerCase())
    .filter(Boolean);

  return [...new Set(methods)];
}

async function paymongoRequest(path, options = {}) {
  const authHeader = paymongoAuth();
  if (!authHeader) {
    const error = new Error("Payment provider not configured (missing secret)");
    error.status = 500;
    throw error;
  }

  const response = await fetch(`${PAYMONGO_BASE}${path}`, {
    ...options,
    headers: {
      Authorization: `Basic ${authHeader}`,
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error("PayMongo request failed");
    error.status = 502;
    error.details = data?.errors || data;
    throw error;
  }

  return data;
}

function customerBillingForOrder(order) {
  const firstName = order.user?.first_name || "";
  const lastName = order.user?.last_name || "";
  const fullName = `${firstName} ${lastName}`.trim() || `Order #${order.id}`;

  return {
    name: fullName,
    email: order.user?.email || undefined,
    phone: order.user?.phone || undefined,
    address: {
      line1:
        order.billing_address ||
        order.shipping_address ||
        order.user?.address ||
        "Philippines",
      country: "PH",
    },
  };
}

// POST /api/payments/checkout — create a PayMongo Checkout Session for an order
app.get("/api/user/:id/payment-logs", async (req, res) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId)) return res.status(400).json({ message: "Invalid userId" });

  try {
    const orders = await prisma.order.findMany({
      where: { userId, deleted_at: null },
      include: {
        user: true,
        items: { include: { product: true } },
      },
      orderBy: { createdAt: "desc" },
    });

    res.json(orders.map((order) => buildReceiptPayload(order)));
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to fetch payment logs" });
  }
});

app.get("/api/orders/:id/receipt", async (req, res) => {
  const orderId = parseInt(req.params.id);
  if (isNaN(orderId))
    return res.status(400).json({ message: "Invalid orderId" });

  try {
    const order = await prisma.order.findUnique({
      where: { id: orderId },
      include: {
        user: true,
        items: { include: { product: true } },
      },
    });

    if (!order || order.deleted_at) {
      return res.status(404).json({ message: "Order not found" });
    }

    res.json(buildReceiptPayload(order));
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to fetch receipt" });
  }
});

app.post("/api/orders/:id/return-complaint", async (req, res) => {
  const orderId = parseInt(req.params.id);
  const { userId, reason, details } = req.body;

  if (isNaN(orderId))
    return res.status(400).json({ message: "Invalid orderId" });
  if (!reason || !String(reason).trim()) {
    return res.status(400).json({ message: "Complaint reason is required" });
  }

  try {
    const order = await prisma.order.findUnique({
      where: { id: orderId },
      include: {
        user: true,
        items: { include: { product: true } },
      },
    });

    if (!order || order.deleted_at) {
      return res.status(404).json({ message: "Order not found" });
    }

    if (userId && order.userId !== parseInt(userId)) {
      return res.status(403).json({ message: "Order does not belong to user" });
    }

    if (order.payment_status !== "paid" || order.status !== "delivered") {
      return res.status(400).json({
        message:
          "Return complaints can only be submitted after a paid order is delivered.",
      });
    }

    const productNames = (order.items || [])
      .map((item) => item.product?.name || `Product #${item.productId}`)
      .join(", ");
    const customerName =
      [order.user?.first_name, order.user?.last_name].filter(Boolean).join(" ") ||
      "Customer";
    const customerEmail = order.user?.email || "";

    const inquiry = await prisma.inquiry.create({
      data: {
        userId: order.userId,
        product_title: productNames || `Order #${order.id}`,
        subject: `Return complaint for Order #${order.id}`,
        name: customerName,
        email: customerEmail,
        quantity: String(
          (order.items || []).reduce((sum, item) => sum + item.quantity, 0),
        ),
        other: [`Reason: ${reason}`, details && `Details: ${details}`]
          .filter(Boolean)
          .join("\n"),
        status: "new",
      },
    });

    const updatedOrder = await prisma.order.update({
      where: { id: orderId },
      data: { status: "return_requested" },
      include: { items: true, user: true },
    });

    res.status(201).json({
      message: "Return complaint submitted",
      inquiry,
      order: updatedOrder,
      mockEmail: {
        to: customerEmail,
        subject: `Return complaint received - Order #${order.id}`,
        body: `Hi ${customerName}, we received your return complaint for Order #${order.id}. Our staff will review it in the admin inquiries module.`,
      },
    });
  } catch (e) {
    console.error("Return complaint failed:", e);
    res.status(500).json({ message: "Failed to submit return complaint" });
  }
});

app.post("/api/payments/checkout", async (req, res) => {
  const {
    orderId,
    appReturnBase,
    returnBase,
    paymentMethods,
    compactCheckout,
  } = req.body;
  if (!orderId) return res.status(400).json({ message: "orderId is required" });

  try {
    const order = await prisma.order.findUnique({
      where: { id: parseInt(orderId) },
      include: { items: { include: { product: true } } },
    });

    if (!order) return res.status(404).json({ message: "Order not found" });
    if (order.payment_status === "paid")
      return res.status(400).json({ message: "Order already paid" });
    if (!order.proofApproved) {
      return res.status(403).json({
        message:
          "Your order is waiting for admin design approval before payment.",
      });
    }

    const publicFrontendUrl =
      process.env.PUBLIC_FRONTEND_URL ||
      process.env.FRONTEND_URL ||
      "https://project-n80jh.vercel.app";
    const paymentReturnBase =
      appReturnBase ||
      returnBase ||
      process.env.PAYMENT_RETURN_BASE ||
      publicFrontendUrl;
    const buildPaymentReturnUrl = (status) => {
      const needsExtraSlash = /^[a-z][a-z0-9+.-]*:\/\/$/i.test(
        paymentReturnBase,
      );
      const separator =
        needsExtraSlash || !paymentReturnBase.endsWith("/") ? "/" : "";
      return `${paymentReturnBase}${separator}payment/return?orderId=${order.id}&status=${status}`;
    };

    // Build line items from order items
    // Build line items from order items, normalize image URLs and include both
    // `image_url` and `images` (array) in case PayMongo expects either format.
    const lineItems = order.items.map((item) => {
      const rawImageUrl =
        (item.customizations && item.customizations.imageUrl) ||
        (item.product && item.product.images && item.product.images[0]) ||
        undefined;

      // Ensure image URL is absolute. If it's a relative path, prefix with the
      // public web URL, not the APK-only custom return scheme.
      let imageUrl = rawImageUrl;
      if (imageUrl && imageUrl.startsWith("/")) {
        imageUrl = `${publicFrontendUrl.replace(/\/$/, "")}${imageUrl}`;
      }

      return {
        currency: "PHP",
        amount: Math.round(parseFloat(item.unit_price) * 100), // in centavos
        name: item.product?.name || `Item #${item.productId}`,
        quantity: item.quantity,
        image_url: compactCheckout ? undefined : imageUrl || undefined,
        images: !compactCheckout && imageUrl ? [imageUrl] : undefined,
      };
    });

    // Log line items for debugging (remove or reduce in production)
    console.log("PayMongo line items:", JSON.stringify(lineItems, null, 2));

    // If there is a shipping cost embedded in the total vs sum of items, add as a line item
    const itemsTotal = order.items.reduce(
      (sum, item) => sum + parseFloat(item.total_price),
      0,
    );
    const shippingCost = parseFloat(order.total) - itemsTotal;
    if (shippingCost > 0.005) {
      lineItems.push({
        currency: "PHP",
        amount: Math.round(shippingCost * 100),
        name: "Shipping",
        quantity: 1,
      });
    }

    const totalAmountCentavos = Math.round(parseFloat(order.total) * 100);
    const checkoutPaymentMethods = paymongoPaymentMethods(paymentMethods);

    const sessionPayload = {
      data: {
        attributes: {
          line_items: lineItems,
          payment_method_types: checkoutPaymentMethods,
          success_url: buildPaymentReturnUrl("success"),
          cancel_url: buildPaymentReturnUrl("cancelled"),
          description: `PrintHub Order #${order.id}`,
          reference_number: String(order.id),
          metadata: { order_id: String(order.id) },
          billing: order.billing_address
            ? {
                name: `Order #${order.id}`,
                address: { line1: order.billing_address, country: "PH" },
              }
            : undefined,
        },
      },
    };

    const authHeader = paymongoAuth();
    if (!authHeader) {
      console.error(
        "PayMongo checkout attempted but PAYMONGO_SECRET_KEY is not configured",
      );
      return res
        .status(500)
        .json({ message: "Payment provider not configured (missing secret)" });
    }

    const pmRes = await fetch(`${PAYMONGO_BASE}/checkout_sessions`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${authHeader}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(sessionPayload),
    });

    const pmData = await pmRes.json();

    if (!pmRes.ok) {
      console.error("PayMongo error:", pmData);
      return res.status(502).json({
        message: "Failed to create payment session",
        details: pmData?.errors || pmData,
      });
    }

    const sessionId = pmData.data.id;
    const checkoutUrl = pmData.data.attributes.checkout_url;

    // Save session info on the order
    await prisma.order.update({
      where: { id: order.id },
      data: {
        paymongo_session_id: sessionId,
        checkout_url: checkoutUrl,
        payment_status: "awaiting_payment",
      },
    });

    res.json({ checkout_url: checkoutUrl, session_id: sessionId });
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ message: e.message || "Internal server error" });
  }
});

// GET /api/payments/:orderId/status — poll payment status (fallback for missed webhooks)
// POST /api/payments/qrph — create a live QR Ph code customers can scan with GCash/Maya/banks
app.post("/api/payments/qrph", async (req, res) => {
  const { orderId } = req.body || {};
  if (!orderId) return res.status(400).json({ message: "orderId is required" });

  try {
    const order = await prisma.order.findUnique({
      where: { id: parseInt(orderId) },
      include: {
        user: true,
        items: { include: { product: true } },
      },
    });

    if (!order) return res.status(404).json({ message: "Order not found" });
    if (order.payment_status === "paid") {
      return res.status(400).json({ message: "Order already paid" });
    }
    if (!order.proofApproved) {
      return res.status(403).json({
        message:
          "Your order is waiting for admin design approval before payment.",
      });
    }

    const amount = Math.round(parseFloat(order.total) * 100);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ message: "Invalid order total" });
    }

    const intent = await paymongoRequest("/payment_intents", {
      method: "POST",
      body: JSON.stringify({
        data: {
          attributes: {
            amount,
            currency: "PHP",
            payment_method_allowed: ["qrph"],
            capture_type: "automatic",
            description: `PrintHub Order #${order.id}`,
            statement_descriptor: "PrintHub",
            metadata: { order_id: String(order.id) },
          },
        },
      }),
    });

    const intentId = intent.data.id;
    const clientKey = intent.data.attributes.client_key;

    const paymentMethod = await paymongoRequest("/payment_methods", {
      method: "POST",
      body: JSON.stringify({
        data: {
          attributes: {
            type: "qrph",
            billing: customerBillingForOrder(order),
          },
        },
      }),
    });

    const attached = await paymongoRequest(`/payment_intents/${intentId}/attach`, {
      method: "POST",
      body: JSON.stringify({
        data: {
          attributes: {
            payment_method: paymentMethod.data.id,
            client_key: clientKey,
          },
        },
      }),
    });

    const attrs = attached.data.attributes || {};
    const qrImageUrl = attrs.next_action?.code?.image_url;

    if (!qrImageUrl) {
      return res.status(502).json({
        message: "PayMongo did not return a QR code. Please try again.",
      });
    }

    await prisma.order.update({
      where: { id: order.id },
      data: {
        paymongo_session_id: intentId,
        checkout_url: null,
        payment_status: "awaiting_payment",
        payment_method: "qrph",
      },
    });

    res.json({
      order_id: order.id,
      amount,
      currency: "PHP",
      payment_intent_id: intentId,
      qr_image_url: qrImageUrl,
      expires_in_seconds: 30 * 60,
    });
  } catch (e) {
    console.error("PayMongo QR Ph error:", e.details || e);
    res.status(e.status || 500).json({
      message:
        e.message === "PayMongo request failed"
          ? "Failed to create PayMongo QR payment"
          : e.message || "Internal server error",
      details: e.details,
    });
  }
});

app.get("/api/payments/:orderId/status", async (req, res) => {
  const orderId = parseInt(req.params.orderId);
  if (isNaN(orderId))
    return res.status(400).json({ message: "Invalid orderId" });

  try {
    const order = await prisma.order.findUnique({
      where: { id: orderId },
      include: {
        user: true,
        items: { include: { product: true } },
      },
    });

    if (!order) return res.status(404).json({ message: "Order not found" });

    // If already marked paid in DB, return without calling PayMongo
    if (order.payment_status === "paid") {
      return res.json({
        payment_status: "paid",
        order,
        receipt: buildReceiptPayload(order),
      });
    }

    // If we have a QR Ph Payment Intent, check PayMongo for the latest status
    if (order.paymongo_session_id?.startsWith("pi_")) {
      const pmData = await paymongoRequest(
        `/payment_intents/${order.paymongo_session_id}`,
        { method: "GET" },
      );
      const attrs = pmData.data.attributes || {};
      const payments = Array.isArray(attrs.payments) ? attrs.payments : [];
      const paidPayment = payments.find((payment) => {
        const paymentStatus = payment?.attributes?.status;
        return paymentStatus === "paid" || paymentStatus === "succeeded";
      });

      if (attrs.status === "succeeded" || paidPayment) {
        const paidOrder = await prisma.order.update({
          where: { id: orderId },
          data: {
            payment_status: "paid",
            status: "confirmed",
            payment_method:
              paidPayment?.attributes?.source?.type ||
              attrs.payment_method_allowed?.[0] ||
              "qrph",
            payment_reference: paidPayment?.id || order.paymongo_session_id,
          },
          include: {
            user: true,
            items: { include: { product: true } },
          },
        });

        const paymentNotification = await notifyPaymentConfirmation(paidOrder);
        const statusNotification = await notifyOrderStatus(
          paidOrder,
          "confirmed",
        );

        return res.json({
          payment_status: "paid",
          order: paidOrder,
          receipt: buildReceiptPayload(paidOrder),
          notifications: [paymentNotification, statusNotification],
        });
      }
    }

    // If we have a session ID, check PayMongo for the latest status
    if (order.paymongo_session_id) {
      const pmRes = await fetch(
        `${PAYMONGO_BASE}/checkout_sessions/${order.paymongo_session_id}`,
        {
          headers: {
            Authorization: `Basic ${paymongoAuth()}`,
            Accept: "application/json",
          },
        },
      );

      if (pmRes.ok) {
        const pmData = await pmRes.json();
        const attrs = pmData.data.attributes;
        const pmStatus = attrs.payment_intent?.attributes?.status;
        const pmPaymentMethod = attrs.payment_method_used || null;
        const payments = Array.isArray(attrs.payments) ? attrs.payments : [];
        const hasPaidPayment = payments.some((payment) => {
          const paymentStatus = payment?.attributes?.status;
          return paymentStatus === "paid" || paymentStatus === "succeeded";
        });

        if (pmStatus === "succeeded" || hasPaidPayment) {
          // Retrieve payment reference from linked payments if available
          const reference =
            payments.length > 0 ? payments[0].id : order.paymongo_session_id;

          const paidOrder = await prisma.order.update({
            where: { id: orderId },
            data: {
              payment_status: "paid",
              status: "confirmed",
              payment_method: pmPaymentMethod,
              payment_reference: reference,
            },
            include: {
              user: true,
              items: { include: { product: true } },
            },
          });

          const paymentNotification = await notifyPaymentConfirmation(paidOrder);
          const statusNotification = await notifyOrderStatus(
            paidOrder,
            "confirmed",
          );

          return res.json({
            payment_status: "paid",
            order: paidOrder,
            receipt: buildReceiptPayload(paidOrder),
            notifications: [paymentNotification, statusNotification],
          });
        }
      }
    }

    res.json({ payment_status: order.payment_status, order });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Internal server error" });
  }
});

// POST /api/payments/webhook — PayMongo webhook handler
// Register this URL in app.paymongo.com → Developers → Webhooks
app.post(
  "/api/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    // Acknowledge quickly to avoid PayMongo retrying
    res.sendStatus(200);

    try {
      const webhookSecret = process.env.PAYMONGO_WEBHOOK_SECRET;

      // Verify signature if secret is configured
      if (
        webhookSecret &&
        webhookSecret !== "whsec_REPLACE_WITH_YOUR_WEBHOOK_SECRET"
      ) {
        const sigHeader = req.headers["paymongo-signature"];
        if (!sigHeader) {
          console.warn("PayMongo webhook: missing signature header — skipping");
          return;
        }

        // Signature format: t=<timestamp>,te=<test_sig>,li=<live_sig>
        const parts = sigHeader.split(",").reduce((acc, part) => {
          const [k, v] = part.split("=");
          acc[k] = v;
          return acc;
        }, {});

        const timestamp = parts.t;
        const toSign = `${timestamp}.${req.body.toString()}`;
        const crypto = require("crypto");
        const expectedSig = crypto
          .createHmac("sha256", webhookSecret)
          .update(toSign)
          .digest("hex");

        const receivedSig = parts.te || parts.li; // test env uses 'te'
        if (receivedSig !== expectedSig) {
          const shortRec = String(receivedSig || "").slice(0, 8);
          const shortExp = String(expectedSig || "").slice(0, 8);
          console.warn(
            `PayMongo webhook: signature mismatch — received=${shortRec} expected=${shortExp} — ignoring`,
          );
          return;
        }
      }

      const payload = JSON.parse(req.body.toString());
      const eventType = payload?.data?.attributes?.type;
      const eventData = payload?.data?.attributes?.data;

      console.log(`PayMongo webhook received: ${eventType}`);

      if (
        eventType === "checkout_session.payment.paid" ||
        eventType === "payment.paid"
      ) {
        const attrs = eventData?.attributes || {};
        const metadata =
          attrs.metadata || eventData?.attributes?.metadata || {};
        let orderId =
          parseInt(metadata.order_id) ||
          parseInt(eventData?.attributes?.reference_number);

        if (!orderId && attrs.payment_intent_id) {
          const order = await prisma.order.findFirst({
            where: { paymongo_session_id: attrs.payment_intent_id },
            select: { id: true },
          });
          orderId = order?.id;
        }

        if (!orderId) {
          console.warn(
            "PayMongo webhook: could not determine orderId from event",
          );
          return;
        }

        const paymentMethod =
          attrs.payment_method_type || attrs.source?.type || null;
        const paymentReference = eventData?.id || null;

        const paidOrder = await prisma.order.update({
          where: { id: orderId },
          data: {
            payment_status: "paid",
            status: "confirmed",
            payment_method: paymentMethod,
            payment_reference: paymentReference,
          },
          include: {
            user: true,
            items: { include: { product: true } },
          },
        });
        await notifyPaymentConfirmation(paidOrder);
        await notifyOrderStatus(paidOrder, "confirmed");

        console.log(`✅ Order #${orderId} marked as paid via PayMongo`);
      }
    } catch (e) {
      console.error("PayMongo webhook processing error:", e);
    }
  },
);

// Start server. Run migrations only when explicitly requested.
(async () => {
  // Log PayMongo configuration status to help with live conversion
  function checkPaymongoConfig() {
    const key = process.env.PAYMONGO_SECRET_KEY || null;
    const webhook = process.env.PAYMONGO_WEBHOOK_SECRET || null;
    if (!key) {
      console.warn(
        "⚠️ PAYMONGO_SECRET_KEY is not set. Payments will fail until configured.",
      );
    } else if (key.startsWith("sk_live_") || key.startsWith("live_")) {
      console.log("✅ Using live PayMongo secret key");
    } else if (key.startsWith("sk_test_") || key.startsWith("test_")) {
      console.warn(
        "⚠️ Using PayMongo test key. Switch to live key for production.",
      );
    } else {
      console.log("PayMongo secret key appears set (unknown prefix)");
    }

    if (!webhook) {
      console.warn(
        "⚠️ PAYMONGO_WEBHOOK_SECRET is not set. Webhook signature verification disabled.",
      );
    }
  }

  checkPaymongoConfig();
if (process.env.RUN_MIGRATIONS === "true") {
    try {
      // Run database migrations
      const { execSync } = require("child_process");
      console.log("Running Prisma migrations...");
      execSync("npx prisma migrate deploy", { stdio: "inherit" });
      console.log("Migrations completed");
    } catch (e) {
      console.log("Migration warning (may already be up to date):", e.message);
    }
  } else {
    console.log("Skipping Prisma migrations on startup.");
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`✅ Server running on port ${PORT}`);
  });
})();
