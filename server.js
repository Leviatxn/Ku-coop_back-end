const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;


const app = express();
app.use(bodyParser.json());



// Enable CORS
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

// ตั้งค่าการเชื่อมต่อกับฐานข้อมูล
const db = mysql.createConnection({
    host: '25.14.131.252',
    user: 'remote_user',
    password: '1234',
    database: 'kucoop_project' 
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed: ", err);
    } else {
        console.log("Connected to the database successfully!");
    }
});

// Session configuration
require('dotenv').config();
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // กำหนดอายุ session
}));

app.use(passport.initialize());
app.use(passport.session());


// Passport Google Strategy
passport.use(new GoogleStrategy({
  clientID: '742020514079-4bt0iavoi21sdm0rkeubueu34iq1v1l0.apps.googleusercontent.com',
  clientSecret: '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',
  callbackURL: '/auth/google/callback'
},  (accessToken, refreshToken, profile, done) => {
  console.log('Google Profile:', profile);
  const email = profile.emails[0].value;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, result) => {
    if (err) return done(err);

    if (result.length === 0) {
      const insertQuery = 'INSERT INTO users (email, is_profile_complete) VALUES (?, ?)';
      db.query(insertQuery, [email, false], (err) => {
        if (err) return done(err);
        return done(null, { email, isFirstLogin: true }); // ส่ง email และ isFirstLogin ให้ serializeUser
      });
    } else {
      const isFirstLogin = !result[0].is_profile_complete;
      return done(null, { email, isFirstLogin }); // ส่ง email และ isFirstLogin ให้ serializeUser
    }
  });
}));

passport.serializeUser((user, done) => {
  console.log('Serializing user:', user); // Debug log
  done(null, user.email); // บันทึก email หรือ identifier ลง session
});

passport.deserializeUser((email, done) => {
  console.log('Deserializing user with email:', email); // Debug log
  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, result) => {
    if (err){
      console.error('Database query Error:', err);
      return done(err);
    } 
    if (result.length === 0) return done(null, false);
    done(null, result[0]);
  });
});

const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client("742020514079-4bt0iavoi21sdm0rkeubueu34iq1v1l0.apps.googleusercontent.com");

async function verifyToken(idToken) {
  const ticket = await client.verifyIdToken({
    idToken,
    audience: "742020514079-4bt0iavoi21sdm0rkeubueu34iq1v1l0.apps.googleusercontent.com", // ตรวจสอบว่า token มาจาก client ของคุณ
  });
  const payload = ticket.getPayload();
  return payload;
}

// Google Auth Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

//Auth Callback
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    console.log('Session after Google login:', req.session);
    console.log('User after Google login:', req.user);
    console.log('User email:', req.user.email);
    const isFirstLogin = req.user.isFirstLogin;
    const redirectUrl = isFirstLogin
      ? 'http://localhost:3000/register'
      : 'http://localhost:3000/home';
    res.redirect(redirectUrl);
  }
);


// Register User
app.post('/register', async (req, res) => {
  console.log('Session in /register:', req.session); // Debug session
  console.log('req.user in /register:', req.user); // Debug req.user
  if (!req.user) {
    console.log('Unauthorized req.user:', req.user);
    return res.status(401).json({ message: 'Unauthorized. Please login through Google first.' });
  }
  const { username, student_id, department, phone_num, password } = req.body;
  console.log('req.body in /register:', req.body);
  const email = req.user.email; // Email should now be accessible via req.user

  if (!username || !student_id || !department || !phone_num || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const query = 'UPDATE users SET username = ?, student_id = ?, department = ?, phone_num = ?, password = ?, is_profile_complete = ? WHERE email = ?';
  db.query(query, [username, student_id, department, phone_num, hashedPassword, 1, email], (err, result) => {
    if (err) {
      console.error('Database Update Error:', err); // แสดง error
      return res.status(500).json({ message: 'Error registering user.' });
    }
    res.json({ message: 'Registration complete!' });
  });
});

//Google Login
app.post("/google-login", async (req, res) => {
  const { idToken } = req.body;

  try {
    const payload = await verifyToken(idToken);
    const email = payload.email;

    const query = "SELECT * FROM users WHERE email = ?";
    db.query(query, [email], (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (result.length === 0) {
        return res.status(404).json({ error: "User not found. Please register first." });
      }

      const user = result[0];
      const token = jwt.sign({ studentId: user.student_id }, "secret_key", { expiresIn: "1h" });

      res.json({
        message: "Google Login successful",
        token,
        student_id: user.student_id,
        username: user.username,
        is_profile_complete: user.is_profile_complete,
      });
    });
  } catch (err) {
    console.error("Token verification error:", err);
    res.status(401).json({ error: "Invalid Google ID Token" });
  }
});


//Login
app.post("/login", (req, res) => {
  const { student_id, password } = req.body;

  const query = "SELECT * FROM users WHERE student_id = ?";
  db.query(query, [student_id], (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.length === 0) return res.status(404).json({ error: "User not found" });

      const user = result[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) return res.status(500).json({ error: "Error comparing passwords" });
          if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

          const token = jwt.sign({ studentId: user.student_id }, "secret_key", { expiresIn: "1h" });
          res.json({ message: "Login successful", token, student_id: user.student_id });
      });
  });
});

//API ดึงข้อมูล Profile
app.get("/user/:student_id", (req, res) => {
  const { student_id } = req.params;

  const query = "SELECT username, email, department, phone_num, is_profile_complete,student_id, role FROM users WHERE student_id = ?";
  db.query(query, [student_id], (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.length === 0) return res.status(404).json({ error: "User not found" });

      res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
  });
});


// Start Server
app.listen(5000, () => {
  console.log('Server is running on http://localhost:5000');
});