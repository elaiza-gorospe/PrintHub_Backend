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
  database: 'printhubdb'
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
          role: user.role === 1 ? 'admin' : 'user'
        }
      });
    });
  });
});

// otp regis
const otpStore = {};

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: 'aizducut@gmail.com',
    pass: 'zvec ihfo tqaa huyw',
  },
});

// send otp
app.post('/api/register/send-otp', (req, res) => {
  const { firstName, lastName, phone, address, email, password } = req.body;

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ message: 'Required fields missing' });
  }

  // Check if email is already registered
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    if (results.length > 0) return res.status(400).json({ message: 'Email is already registered' });

    // If not registered, generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP

    // store otp
    otpStore[email] = { otp, data: { firstName, lastName, phone, address, email, password }, expires: Date.now() + 5 * 60 * 1000 };

    const mailOptions = {
      from: 'aizducut@gmail.com',
      to: email,
      subject: 'Your PMG Registration OTP',
      text: `Your OTP code is: ${otp}. It expires in 5 minutes.`,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) return res.status(500).json({ message: 'Failed to send OTP', error: err });
      res.json({ message: 'OTP sent successfully' });
    });
  });
});

// verify otp
app.post('/api/register/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  if (!otpStore[email]) {
    return res.status(400).json({ message: 'No OTP found for this email or OTP expired' });
  }

  const record = otpStore[email];

  if (Date.now() > record.expires) {
    delete otpStore[email];
    return res.status(400).json({ message: 'OTP expired' });
  }

  if (parseInt(otp) !== record.otp) {
    return res.status(400).json({ message: 'Incorrect OTP' });
  }

  const { firstName, lastName, phone, address, password } = record.data;

  // Hash password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ message: 'Error hashing password' });

    db.query(
      'INSERT INTO users (first_name, last_name, phone, address, email, password) VALUES (?, ?, ?, ?, ?, ?)',
      [firstName, lastName, phone, address, email, hashedPassword],
      (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error', error: err });

        delete otpStore[email]; // remove OTP
        res.json({ message: 'User registered successfully' });
      }
    );
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
