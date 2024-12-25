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
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport Google Strategy
passport.use(new GoogleStrategy({
  clientID: '742020514079-4bt0iavoi21sdm0rkeubueu34iq1v1l0.apps.googleusercontent.com',
  clientSecret: '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',
  callbackURL: '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails[0].value;
  if (!email.endsWith('@ku.th')) {
    return done(null, false, { message: 'Unauthorized domain' });
  }

  const query = 'SELECT * FROM user WHERE email = ?';
  db.query(query, [email], (err, result) => {
    if (err) return done(err);
    if (result.length === 0) {
      const insertQuery = 'INSERT INTO user (email, password) VALUES (?, ?)';
      db.query(insertQuery, [email, 'google-auth'], (err) => {
        if (err) return done(err);
        return done(null, profile);
      });
    } else {
      return done(null, profile);
    }
  });
}));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Google Auth Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('http://localhost:3000'); // Redirect to React frontend
  }
);

// Register User
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const query = 'INSERT INTO users (email, password) VALUES (?, ?)';
  db.query(query, [email, hashedPassword], (err, result) => {
    if (err) return res.status(500).json({ message: 'Error registering user.' });
    res.json({ message: 'User registered successfully!' });
  });
});

// Login User
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, result) => {
    if (err) return res.status(500).json({ message: 'Server error.' });
    if (result.length === 0) return res.status(401).json({ message: 'User not found.' });

    const validPassword = await bcrypt.compare(password, result[0].password);
    if (!validPassword) return res.status(401).json({ message: 'Invalid credentials.' });

    const token = jwt.sign({ id: result[0].id }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ message: 'Login successful!', token });
  });
});

// Start Server
app.listen(5000, () => {
  console.log('Server is running on http://localhost:5000');
});