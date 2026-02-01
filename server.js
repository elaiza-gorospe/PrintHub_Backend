const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL Connection
const db = mysql.createConnection({
  host: '127.0.0.1',
  user: 'root',
  password: 'root',
  database: 'printhub_db'
});

db.connect(err => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// ------------------ LOGIN ENDPOINT ------------------
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    if (results.length === 0) return res.status(400).json({ message: 'Email not registered' });

    const user = results[0];

    bcrypt.compare(password, user.password, (err, match) => {
      if (err) return res.status(500).json({ message: 'Error checking password' });
      if (!match) return res.status(400).json({ message: 'Incorrect password' });

      res.json({
        message: 'Login successful',
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          role: user.role === 0 ? 'admin' : 'user'
        }
      });
    });
  });
});

// ------------------ OTP REGISTRATION ------------------
const otpStore = {};

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: 'aizducut@gmail.com',
    pass: 'zvec ihfo tqaa huyw',
  },
});

// ------------------ SEND OTP (REGISTRATION) ------------------
app.post('/api/register/send-otp', (req, res) => {
  const { firstName, lastName, phone, address, email, password } = req.body;

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ message: 'Required fields missing' });
  }

  const nameRegex = /^[A-Za-z\s]+$/;
  if (!nameRegex.test(firstName) || !nameRegex.test(lastName)) {
    return res.status(400).json({ message: 'Name can only contain letters and spaces' });
  }

  const phoneRegex = /^\+63\d{10}$/;
  if (!phoneRegex.test(phone)) {
    return res.status(400).json({ message: 'Phone number must start with +63 and contain 10 digits after it' });
  }

  const uppercase = /[A-Z]/.test(password);
  const number = /\d/.test(password);
  const special = /[^A-Za-z0-9]/.test(password);
  const length = password.length >= 8 && password.length <= 12;

  if (!uppercase || !number || !special || !length) {
    return res.status(400).json({ message: 'Password does not meet all criteria' });
  }

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    if (results.length > 0) return res.status(400).json({ message: 'Email is already registered' });

    const otp = Math.floor(100000 + Math.random() * 900000);

    otpStore[email] = {
      otp,
      data: { firstName, lastName, phone, address, email, password },
      expires: Date.now() + 5 * 60 * 1000
    };

    const mailOptions = {
      from: 'aizducut@gmail.com',
      to: email,
      subject: 'Your PMG Registration OTP',
      text: `Your OTP code is: ${otp}. It expires in 5 minutes.`,
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) return res.status(500).json({ message: 'Failed to send OTP', error: err });
      res.json({ message: 'OTP sent successfully' });
    });
  });
});

// ------------------ VERIFY OTP (REGISTRATION) ------------------
app.post('/api/register/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  if (!otpStore[email]) return res.status(400).json({ message: 'No OTP found or expired' });

  const record = otpStore[email];

  if (Date.now() > record.expires) {
    delete otpStore[email];
    return res.status(400).json({ message: 'OTP expired' });
  }

  if (parseInt(otp) !== record.otp) return res.status(400).json({ message: 'Incorrect OTP' });

  const { firstName, lastName, phone = '', address = '', password } = record.data;

  const role = 1;

  db.query('SELECT id FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error checking email', error: err.code });
    if (results.length > 0) {
      delete otpStore[email];
      return res.status(400).json({ message: 'Email already registered' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ message: 'Error hashing password', error: err.message });

      const insertQuery = `
        INSERT INTO users (first_name, last_name, phone, address, email, password, role)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;
      const values = [firstName, lastName, phone, address, email, hashedPassword, role];

      db.query(insertQuery, values, (err) => {
        if (err) {
          console.error('MySQL Insert Error:', err.code, err.sqlMessage);
          return res.status(500).json({ message: 'Database insert error', error: err.code });
        }

        delete otpStore[email];
        res.json({ message: 'User registered successfully' });
      });
    });
  });
});

// =====================================================
// ✅ FORGOT PASSWORD OTP (NEW)
// =====================================================
const resetOtpStore = {};

// SEND OTP (FORGOT PASSWORD)
app.post('/api/password/send-otp', (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: 'Email is required' });

  db.query('SELECT id FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    if (results.length === 0) return res.status(400).json({ message: 'Email not registered' });

    const otp = Math.floor(100000 + Math.random() * 900000);

    resetOtpStore[email] = {
      otp,
      expires: Date.now() + 5 * 60 * 1000,
      verified: false,
    };

    const mailOptions = {
      from: 'aizducut@gmail.com',
      to: email,
      subject: 'Your Password Reset OTP',
      text: `Your OTP code is: ${otp}. It expires in 5 minutes.`,
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) return res.status(500).json({ message: 'Failed to send OTP', error: err });
      res.json({ message: 'OTP sent successfully' });
    });
  });
});

// VERIFY OTP (FORGOT PASSWORD)
app.post('/api/password/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) return res.status(400).json({ message: 'Email and OTP are required' });
  if (!resetOtpStore[email]) return res.status(400).json({ message: 'No OTP found or expired' });

  const record = resetOtpStore[email];

  if (Date.now() > record.expires) {
    delete resetOtpStore[email];
    return res.status(400).json({ message: 'OTP expired' });
  }

  if (parseInt(otp) !== record.otp) {
    return res.status(400).json({ message: 'Incorrect OTP' });
  }

  resetOtpStore[email].verified = true;
  res.json({ message: 'OTP verified' });
});

// RESET PASSWORD (ONLY AFTER OTP VERIFIED)
app.post('/api/reset-password', (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({ message: 'Email and new password are required' });
  }

  const record = resetOtpStore[email];
  if (!record || !record.verified) {
    return res.status(403).json({ message: 'OTP not verified' });
  }

  bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ message: 'Error hashing password' });

    db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (err) => {
      if (err) return res.status(500).json({ message: 'Database error', error: err });

      delete resetOtpStore[email];
      res.json({ message: 'Password reset successful' });
    });
  });
});

// ------------------ CREATE DEFAULT ADMIN ------------------
const createAdmin = async () => {
  const email = 'admin@printhub.com';
  const password = 'admin123';
  const firstName = 'Admin';
  const lastName = 'User';
  const phone = '09123456789';
  const address = 'PrintHub Main Office';
  const role = 0;

  try {
    const [results] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (results.length > 0) {
      console.log('Admin account already exists');
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.promise().query(
      'INSERT INTO users (first_name, last_name, phone, address, email, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [firstName, lastName, phone, address, email, hashedPassword, role]
    );

    console.log('Default admin account created successfully');
  } catch (err) {
    console.error('Error creating admin account:', err);
  }
};

createAdmin();

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
