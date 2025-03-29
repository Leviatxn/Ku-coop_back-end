const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer = require('multer');
const path = require("path");


const app = express();

//Middlerware
app.use(bodyParser.json());
app.use(express.static("uploads"));
app.use(express.urlencoded({ extended: true }));


app.use("/uploads", express.static(path.join(__dirname, "uploads")));



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
    audience: "742020514079-4bt0iavoi21sdm0rkeubueu34iq1v1l0.apps.googleusercontent.com",
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
    const email = req.user.email;
    try{
      if(isFirstLogin){
        res.redirect('http://localhost:3000/register');
      }
      else{
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
          const token = jwt.sign({ student_id: user.student_id , role: user.role }, process.env.JWT_SECRET || "default_secret_key", { expiresIn: "1h" });
            
          // ✅ เก็บ Token ใน Session
          req.session.token = token;
          req.session.role = user.role;
          req.session.student_id = user.student_id;

          // ✅ ปิด Popup แล้วให้ React ดึง Token ผ่าน API `/auth/user`
          res.send(`<script>
              window.opener && window.opener.postMessage("success", "http://localhost:3000");
              window.close();
          </script>`);
        });
      }
    }catch (err) {
    console.error("Token verification error:", err);
    res.status(401).json({ error: "Invalid Google ID Token" });
    }
  }
);

app.get("/auth/user", (req, res) => {
  if (!req.session.token) {
      return res.status(401).json({ error: "Not authenticated" });
  }
  res.json({ student_id: req.session.student_id, token: req.session.token });
});


// Register User
app.post('/register', async (req, res) => {
  console.log('Session in /register:', req.session); // Debug session
  console.log('req.user in /register:', req.user); // Debug req.user
  console.log('req.body in /register:', req.body);


  if( req.body.role == 'student'){
    console.log(req.body.role);

    if (!req.user) {
      console.log('Unauthorized req.user:', req.user);
      return res.status(401).json({ message: 'Unauthorized. Please login through Google first.' });
    }
    const { username, student_id, phone_num, password,role } = req.body;
    const email = req.user.email; // Email should now be accessible via req.user

    if (!username||!student_id|| !phone_num || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'UPDATE users SET username = ?, student_id = ?, phone_num = ?, password = ?, is_profile_complete = ? ,role = ? WHERE email = ?';
    db.query(query, [username, student_id, phone_num, hashedPassword, 1,role, email], (err, result) => {
      if (err) {
        console.error('Database Update Error:', err); // แสดง error
        return res.status(500).json({ message: 'Error registering user.' });
      }
      res.json({ message: 'Registration complete!' });
    });
  }

  else if(req.body.role == 'admin'){
    console.log(req.body.role)
    const { email,username, student_id, phone_num, password,role } = req.body;
    if (!username||!email|| !phone_num || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const insertQuery = 'INSERT INTO users (username,student_id,phone_num,password,is_profile_complete,role,email) VALUES (?,?,?,?,?,?,?)';
    db.query(insertQuery, [username, student_id, phone_num, hashedPassword, 1,role, email], (err, result) => {
      if (err) {
        console.error('Database Update Error:', err); // แสดง error
        return res.status(500).json({ message: 'Error registering user.' });
      }
      res.json({ message: 'Registration complete!' });
    });
  }

  else if(req.body.role == 'professor'){
    console.log(req.body.role)
    const { email,username, student_id, phone_num, password,role } = req.body;
    if (!username||!email|| !phone_num || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const insertQuery = 'INSERT INTO users (username,student_id,phone_num,password,is_profile_complete,role,email) VALUES (?,?,?,?,?,?,?)';
    db.query(insertQuery, [username, student_id, phone_num, hashedPassword, 1,role, email], (err, result) => {
      if (err) {
        console.error('Database Update Error:', err); // แสดง error
        return res.status(500).json({ message: 'Error registering user.' });
      }
      res.json({ message: 'Registration complete!' });
    });
  }

  else if(req.body.role == 'company'){
    console.log(req.body.role)
    const { email,username, student_id, phone_num, password,role } = req.body;
    if (!username||!email|| !phone_num || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const insertQuery = 'INSERT INTO users (username,student_id,phone_num,password,is_profile_complete,role,email) VALUES (?,?,?,?,?,?,?)';
    db.query(insertQuery, [username, student_id, phone_num, hashedPassword, 1,role, email], (err, result) => {
      if (err) {
        console.error('Database Update Error:', err); // แสดง error
        return res.status(500).json({ message: 'Error registering user.' });
      }
      res.json({ message: 'Registration complete!' });
    });
  }
});



//Login
app.post("/login", (req, res) => {
  const { student_id, password } = req.body;

  const query = "SELECT * FROM users WHERE student_id = ? AND role = ? ";
  db.query(query, [student_id,"student"], (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.length === 0) return res.status(404).json({ error: "User not found" });

      const user = result[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) return res.status(500).json({ error: "Error comparing passwords" });
          if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

          const token = jwt.sign({ student_id: user.student_id , role: user.role },process.env.JWT_SECRET || "default_secret_key", { expiresIn: "1h" });
          res.json({ message: "Login successful", token, student_id: user.student_id });
      });
  });
});

//Admin Login
app.post("/admin-login", (req, res) => {
  console.log(req.body)

  const { email, password } = req.body;

  const query = "SELECT * FROM users WHERE email = ? AND role = ? ";
  db.query(query, [email,"admin"], (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.length === 0) return res.status(404).json({ error: "User not found" });

      const user = result[0];
      console.log(user)
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) return res.status(500).json({ error: "Error comparing passwords" });
          if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

          const token = jwt.sign({ email: user.email , role: user.role }, process.env.JWT_SECRET || "default_secret_key",  { expiresIn: "1h" });
          res.json({ message: "Login successful", token, email: user.email });
      });
  });
});





//Admin Login
app.post("/prof-login", (req, res) => {
  console.log(req.body)

  const { email, password } = req.body;

  const query = "SELECT * FROM users WHERE email = ? AND role = ? ";
  db.query(query, [email,"professor"], (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.length === 0) return res.status(404).json({ error: "User not found" });

      const user = result[0];
      console.log(user)
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) return res.status(500).json({ error: "Error comparing passwords" });
          if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

          const token = jwt.sign({ email: user.email , role: user.role }, process.env.JWT_SECRET || "default_secret_key", { expiresIn: "1h" });
          res.json({ message: "Login successful", token, email: user.email });
      });
  });
});


//Admin Login
app.post("/company-login", (req, res) => {
  console.log(req.body)

  const { email, password } = req.body;

  const query = "SELECT * FROM users WHERE email = ? AND role = ? ";
  db.query(query, [email,"company"], (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.length === 0) return res.status(404).json({ error: "User not found" });

      const user = result[0];
      console.log(user)
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) return res.status(500).json({ error: "Error comparing passwords" });
          if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

          const token = jwt.sign({ email: user.email , role: user.role }, process.env.JWT_SECRET || "default_secret_key",  { expiresIn: "1h" });
          res.json({ message: "Login successful", token, email: user.email });
      });
  });
});


//API ดึงข้อมูล Profile
app.get("/user/:student_id", (req, res) => {
  const { student_id } = req.params;

  const query = "SELECT username, email, phone_num, is_profile_complete,student_id, role FROM users WHERE student_id = ?";
  db.query(query, [student_id], (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.length === 0) return res.status(404).json({ error: "User not found" });

      res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
  });
});

//API ดึงข้อมูล user Sort by role
app.get("/user_by_role/:role", (req, res) => {
  const { role } = req.params;
  const query = "SELECT * FROM users WHERE role = ? ORDER BY username ";
  db.query(query,[role], (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).send("Failed to fetch data");
    } else {
      res.status(200).json(results);
    }
  });
});


//API ดึงข้อมูล Profile Select by Email
app.get("/user-email/:email", (req, res) => {
  const { email } = req.params;
  console.log(email);
  const query = "SELECT username, email, phone_num, is_profile_complete,student_id, role FROM users WHERE email = ?";
  db.query(query, [email], (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.length === 0) return res.status(404).json({ error: "User not found" });

      res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
  });
});

// API ดึงข้อมูล Info
app.get("/user_info/:student_id", (req, res) => {
  const { student_id } = req.params;
  console.log(student_id);
  const query = `
    SELECT 
      first_name, 
      last_name, 
      student_id, 
      major, 
      year, 
      email, 
      phone_number, 
      company_name, 
      current_petition, 
      is_firstappointment, 
      is_secondappointment,
      first_evaluate_state,
      second_evaluate_state,
      current_state,
      coop_state,
      profile_img
    FROM studentsinfo
    WHERE student_id = ?`;

  db.query(query, [student_id], (err, result) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (result.length === 0) return res.status(404).json({ error: "User not found" });

    res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
  });
});


// API ดึงข้อมูล Info
app.get("/coop_info/:student_id", (req, res) => {
  const { student_id } = req.params;
  console.log('coop',student_id);
  const query = `
    SELECT 
      CompanyNameTH,
      CompanyNameEN,
      CompanyAddress,
      CompanyProvince,
      FilePath,
      Allowance,
      CompanyPhoneNumber,
      Coop_StartDate,
      Coop_EndDate
    FROM coopapplication
    WHERE StudentID = ? AND Is_approve = 1;`;

  db.query(query, [student_id], (err, result) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (result.length === 0) return res.status(404).json({ error: "User not found" });

    res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
  });
});

// API ดึงข้อมูล Info
app.get("/first_appointment/:student_id", (req, res) => {
  const { student_id } = req.params;
  console.log(student_id);
  const query = `
    SELECT 
      student_id,
      appointment_date,
      appointment_time,
      appointment_type,
      advisor_id,
      notes,
      status,
      advisor_date,
      advisor_time,
      is_accept,
      travel_type
    FROM appointments1
    WHERE student_id = ?;`;

  db.query(query, [student_id], (err, result) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (result.length === 0) return res.status(404).json({ error: "User not found" });

    res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
  });
});

// API ดึงข้อมูล Info
app.get("/second_appointment/:student_id", (req, res) => {
  const { student_id } = req.params;
  console.log(student_id);
  const query = `
    SELECT 
      student_id,
      appointment_date,
      appointment_time,
      appointment_type,
      advisor_id,
      notes,
      status,
      advisor_date,
      advisor_time,
      is_accept,
      travel_type
    FROM appointments2
    WHERE student_id = ?;`;

  db.query(query, [student_id], (err, result) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (result.length === 0) {
      console.log('error user not found');
      return res.status(404).json({ error: "User not found" });
    }
    res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
  });
});

// API ดึงข้อมูล Info
app.get("/user_info/:student_id", (req, res) => {
  const { student_id } = req.params;
  console.log(student_id);
  const query = `
    SELECT 
      first_name, 
      last_name, 
      student_id, 
      major, 
      year, 
      email, 
      phone_number, 
      company_name, 
      current_petition, 
      lastest_coopapplication, 
      lastest_studentcoopapplication, 
      current_state,
      coop_state,
      profile_img
    FROM studentsinfo
    WHERE student_id = ?`;

  db.query(query, [student_id], (err, result) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (result.length === 0) return res.status(404).json({ error: "User not found" });

    res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
  });
});

//API ดึงข้อมูล user Sort by role
app.get("/user", (req, res) => {

  const query = "SELECT * FROM users ORDER BY username ";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).send("Failed to fetch data");
    } else {
      res.status(200).json(results);
    }
  });
});


// API ดึงข้อมูล Info
app.get("/isCoopstudent/:student_id", (req, res) => {
  const { student_id } = req.params;

  const query = `
    SELECT 
      is_coopstudent
    FROM studentsinfo
    WHERE student_id = ?`;

  db.query(query, [student_id], (err, result) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (result.length === 0) return res.status(404).json({ error: "User not found" });

    res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
  });
});


//API ดึงข้อมูล user 
app.get("/studentsinfo", (req, res) => {

  const query = "SELECT first_name, last_name, student_id, major, year, phone_number,is_coopstudent,company_name,coop_state,is_firstappointment,is_secondappointment FROM studentsinfo ";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).send("Failed to fetch data");
    } else {
      res.status(200).json(results);
    }
  });
});

//API ดึงข้อมูล user 
app.get("/studentsCoopinfo", (req, res) => {

  const query = "SELECT first_name, last_name, student_id, major, year, phone_number,is_coopstudent,company_name,coop_state,is_firstappointment,is_secondappointment FROM studentsinfo WHERE is_coopstudent = 1";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).send("Failed to fetch data");
    } else {
      res.status(200).json(results);
    }
  });
});


// กำหนดที่เก็บไฟล์อัปโหลด
const profile_storage = multer.diskStorage({
  destination: './uploads/userProfile/',
  filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const profile_upload = multer({ storage:profile_storage });
// อัปเดตข้อมูลรูปภาพ
app.put("/addstudent_profile/:student_id", profile_upload.single("profile_img"), (req, res) => {
  const student_id = req.params.student_id;
  const profile_img = req.file ? `/uploads/userProfile/${req.file.filename}` : null;
  console.log(req.file)
  let query = `
    UPDATE studentsinfo 
    SET profile_img=?
    WHERE student_id=?
  `;

  let params = [];
  if (profile_img) params.push(profile_img);
  params.push(student_id);

  db.query(query, params, (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      res.json({ message: "User updated successfully", profile_img });
  });
});

app.post("/addstudentsinfo", (req, res) => {
  console.log(req.body);

  const { student_id, first_name, last_name, major, year, email, phone_number } = req.body;

  const query = `
      INSERT INTO studentsinfo (student_id, first_name, last_name, major, year, email, phone_number) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
      query,
      [student_id, first_name, last_name, major, year, email, phone_number],
      (err, result) => {
          if (err) {
              console.error(err);
              res.status(500).send("Error inserting data");
          } else {
              res.status(201).send("Data inserted successfully");
          }
      }
  );
});

//Post Info
app.put("/updatestudentsinfo/:student_id", (req, res) => {
  const { student_id } = req.params;
  console.log(student_id);
  console.log(req.body);

  const { first_name, last_name, major, year, email, phone_number } = req.body;

  const query = `
    UPDATE studentsinfo 
    SET first_name=?, last_name=?, major=?, year=?, email=?, phone_number=?
    WHERE student_id=?
  `;

  db.query(
    query,
    [first_name, last_name, major, year, email, phone_number,student_id],
    (err, result) => {
      if (err) {
        console.error(err);
        res.status(500).send("Error saving data");
      } else {
        res.status(200).send("Data saved successfully");
      }
    }
  );
});

//API update สถานะ coop และ companyname
app.put("/updateiscoopstudent", (req, res) => {
  console.log(req.body);
  const { is_coopstudent, company_name, student_id} = req.body;

  const query = `
    UPDATE studentsinfo 
    SET is_coopstudent = ?, company_name = ? 
    WHERE student_id = ?
  `;

  db.query(
    query,
    [is_coopstudent, company_name, student_id],
    (err, result) => {
      if (err) {
        console.error(err);
        res.status(500).send("Error saving data");
      } else {
        res.status(200).send("Data saved successfully");
      }
    }
  );
});

//API update สถานะ coop และ companyname
app.put("/updateFirstevaluation/:student_id", (req, res) => {
  const { student_id } = req.params;
  const query = `
    UPDATE studentsinfo 
    SET first_evaluate_state = ?
    WHERE student_id = ?
  `;
  db.query(
    query,
    [ 1 , student_id],
    (err, result) => {
      if (err) {
        console.error(err);
        res.status(500).send("Error saving data");
      } else {
        res.status(200).send("Data saved successfully");
      }
    }
  );
});

//API update สถานะ coop และ companyname
app.put("/updateSecondevaluation/:student_id", (req, res) => {
  const { student_id } = req.params;
  const query = `
    UPDATE studentsinfo 
    SET second_evaluate_state = ?
    WHERE student_id = ?
  `;
  db.query(
    query,
    [ 1 , student_id],
    (err, result) => {
      if (err) {
        console.error(err);
        res.status(500).send("Error saving data");
      } else {
        res.status(200).send("Data saved successfully");
      }
    }
  );
});


//API update สถานะ coop และ companyname
app.put("/updateCoopState/:student_id", (req, res) => {
  const { student_id } = req.params;
  const { currentState } = req.body;
  console.log(currentState)
  const query = `
    UPDATE studentsinfo 
    SET coop_state = ?
    WHERE student_id = ?
  `;
  db.query(
    query,
    [ currentState , student_id],
    (err, result) => {
      if (err) {
        console.error(err);
        res.status(500).send("Error saving data");
      } else {
        res.status(200).send("Data saved successfully");
      }
    }
  );
});

// API สำหรับอัปเดตค่า Is_approve และ Progress_State
app.put("/updateStudentApplication", (req, res) => {
  const { ApplicationID, Is_approve, Progress_State } = req.body;

  // ตรวจสอบข้อมูลที่รับเข้ามา
  if (!ApplicationID || Is_approve === undefined || Progress_State === undefined) {
    return res.status(400).json({ error: "Invalid input data." });
  }

  // คำสั่ง SQL สำหรับอัปเดตข้อมูล
  const sql = `
    UPDATE studentcoopapplication 
    SET Is_approve = ?, Progress_State = ? 
    WHERE ApplicationID = ?
  `;

  // ดำเนินการอัปเดตข้อมูลในฐานข้อมูล
  db.query(sql, [Is_approve, Progress_State, ApplicationID], (err, result) => {
    if (err) {
      console.error("Error updating data:", err);
      res.status(500).json({ error: "Failed to update data." });
    } else {
      res.json({ message: "Data updated successfully.", result });
    }
  });
});

// API สำหรับอัปเดตค่า Is_approve และ Progress_State
app.put("/updateCoopApplication", (req, res) => {
  const { ApplicationID, Is_approve, Progress_State } = req.body;

  // ตรวจสอบข้อมูลที่รับเข้ามา
  if (!ApplicationID || Is_approve === undefined || Progress_State === undefined) {
    return res.status(400).json({ error: "Invalid input data." });
  }

  // คำสั่ง SQL สำหรับอัปเดตข้อมูล
  const sql = `
    UPDATE coopapplication 
    SET Is_approve = ?, Progress_State = ? 
    WHERE ApplicationID = ?
  `;

  // ดำเนินการอัปเดตข้อมูลในฐานข้อมูล
  db.query(sql, [Is_approve, Progress_State, ApplicationID], (err, result) => {
    if (err) {
      console.error("Error updating data:", err);
      res.status(500).json({ error: "Failed to update data." });
    } else {
      res.json({ message: "Data updated successfully.", result });
    }
  });
});



// Update Current Petition
app.post("/current_petition", (req, res) => {
  console.log("Request Headers for /current_petition:", req.headers);
  console.log("Request Body:", req.body);
  const { StudentID, PetitionName } = req.body;

  const query = `
    UPDATE studentsinfo
    SET current_petition = ?
    WHERE student_id = ?
  `;

  db.query(query, [PetitionName, StudentID], (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).send("Error updating data");
    } else {
      res.status(200).send("Data updated successfully");
    }
  });
});

app.post("/addAppointment1/:student_id", (req, res) => {
  console.log("API ถูกเรียกใช้");
  console.log(req.body);
  console.log(" student_id:", req.params);
  const { student_id } = req.params;  // รับค่า student_id จาก URL
  const { appointment_date, appointment_time, Notes } = req.body;
  if ( !appointment_date || !appointment_time ) {
    return res.status(400).json({ error: "กรุณากรอกข้อมูลให้ครบถ้วน" });
  }

  const query = `
    INSERT INTO appointments1 (student_id, appointment_date, appointment_time, notes, status, created_at)
    VALUES (?, ?, ?, ?, 'Scheduled', NOW());
  `;

  db.query(query, [student_id, appointment_date, appointment_time, Notes], (err, result) => {
    if (err) {
      console.error("Insert Error:", err);
      return res.status(500).json({ error: "เกิดข้อผิดพลาดในการเพิ่มข้อมูล" });
    }
    res.status(200).json({ message: "เพิ่มการนัดหมายสำเร็จ", appointment_id: result.insertId });
  });
});
app.put("/updateAppointment1/:student_id", (req, res) => {
  console.log(req.body);

  console.log("student_id:", req.params);

  const { student_id } = req.params;  
  const { appointment_date, appointment_time, Notes } = req.body;

  if (!appointment_date || !appointment_time) {
    return res.status(400).json({ error: "กรุณากรอกข้อมูลให้ครบถ้วน" });
  }

  const query = `
    UPDATE appointments1 
    SET appointment_date = ?, appointment_time = ?, notes = ?, updated_at = NOW()
    WHERE student_id = ?;
  `;

  db.query(query, [appointment_date, appointment_time, Notes, student_id], (err, result) => {
    if (err) {
      console.error("Update Error:", err);
      return res.status(500).json({ error: "เกิดข้อผิดพลาดในการอัปเดตข้อมูล" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "ไม่พบข้อมูลนัดหมายสำหรับ student_id นี้" });
    }

    res.status(200).json({ message: "อัปเดตการนัดหมายสำเร็จ" });
  });
});

app.put("/updateAdvisorInAppointment1/:student_id", (req, res) => {
  console.log(req.body);

  console.log("student_id:", req.params);

  const { student_id } = req.params;  
  const { advisor_date, advisor_time, travel_type,appointment_type } = req.body;


  const query = `
    UPDATE appointments1 
    SET advisor_date = ?, advisor_time = ?, travel_type = ?,appointment_type = ?, updated_at = NOW()
    WHERE student_id = ?;
  `;

  db.query(query, [advisor_date, advisor_time, travel_type,appointment_type, student_id], (err, result) => {
    if (err) {
      console.error("Update Error:", err);
      return res.status(500).json({ error: "เกิดข้อผิดพลาดในการอัปเดตข้อมูล" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "ไม่พบข้อมูลนัดหมายสำหรับ student_id นี้" });
    }

    res.status(200).json({ message: "อัปเดตการนัดหมายสำเร็จ" });
  });
});


app.put("/acceptAppointment1/:student_id", (req, res) => {
  console.log(req.body);

  console.log(" accept student_id:", req.params);

  const { student_id } = req.params;  
  const {is_accept } = req.body;


  const query = `
    UPDATE appointments1 
    SET is_accept = ?, updated_at = NOW()
    WHERE student_id = ?;
  `;

  db.query(query, [is_accept, student_id], (err, result) => {
    if (err) {
      console.error("Update Error:", err);
      return res.status(500).json({ error: "เกิดข้อผิดพลาดในการอัปเดตข้อมูล" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "ไม่พบข้อมูลนัดหมายสำหรับ student_id นี้" });
    }

    res.status(200).json({ message: "อัปเดตการนัดหมายสำเร็จ" });
  });
});



app.post("/addAppointment2/:student_id", (req, res) => {
  console.log("API ถูกเรียกใช้");
  console.log(req.body);
  console.log(" student_id:", req.params);
  const { student_id } = req.params;  // รับค่า student_id จาก URL
  const { appointment_date, appointment_time, Notes } = req.body;
  if ( !appointment_date || !appointment_time ) {
    return res.status(400).json({ error: "กรุณากรอกข้อมูลให้ครบถ้วน" });
  }

  const query = `
    INSERT INTO appointments2 (student_id, appointment_date, appointment_time, notes, status, created_at)
    VALUES (?, ?, ?, ?, 'Scheduled', NOW());
  `;

  db.query(query, [student_id, appointment_date, appointment_time, Notes], (err, result) => {
    if (err) {
      console.error("Insert Error:", err);
      return res.status(500).json({ error: "เกิดข้อผิดพลาดในการเพิ่มข้อมูล" });
    }
    res.status(200).json({ message: "เพิ่มการนัดหมายสำเร็จ", appointment_id: result.insertId });
  });
});
app.put("/updateAppointment2/:student_id", (req, res) => {
  console.log(req.body);

  console.log("student_id:", req.params);

  const { student_id } = req.params;  
  const { appointment_date, appointment_time, Notes } = req.body;

  if (!appointment_date || !appointment_time) {
    return res.status(400).json({ error: "กรุณากรอกข้อมูลให้ครบถ้วน" });
  }

  const query = `
    UPDATE appointments2 
    SET appointment_date = ?, appointment_time = ?, notes = ?, updated_at = NOW()
    WHERE student_id = ?;
  `;

  db.query(query, [appointment_date, appointment_time, Notes, student_id], (err, result) => {
    if (err) {
      console.error("Update Error:", err);
      return res.status(500).json({ error: "เกิดข้อผิดพลาดในการอัปเดตข้อมูล" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "ไม่พบข้อมูลนัดหมายสำหรับ student_id นี้" });
    }

    res.status(200).json({ message: "อัปเดตการนัดหมายสำเร็จ" });
  });
});

app.put("/updateAdvisorInAppointment2/:student_id", (req, res) => {
  console.log(req.body);

  console.log("student_id:", req.params);

  const { student_id } = req.params;  
  const { advisor_date, advisor_time, travel_type,appointment_type } = req.body;

  const query = `
    UPDATE appointments2
    SET advisor_date = ?, advisor_time = ?, travel_type = ?,appointment_type = ?, updated_at = NOW()
    WHERE student_id = ?;
  `;

  db.query(query, [advisor_date, advisor_time, travel_type,appointment_type, student_id], (err, result) => {
    if (err) {
      console.error("Update Error:", err);
      return res.status(500).json({ error: "เกิดข้อผิดพลาดในการอัปเดตข้อมูล" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "ไม่พบข้อมูลนัดหมายสำหรับ student_id นี้" });
    }

    res.status(200).json({ message: "อัปเดตการนัดหมายสำเร็จ" });
  });
});

app.put("/acceptAppointment2/:student_id", (req, res) => {
  console.log(req.body);

  console.log(" accept student_id:", req.params);

  const { student_id } = req.params;  
  const {is_accept } = req.body;


  const query = `
    UPDATE appointments2 
    SET is_accept = ?, updated_at = NOW()
    WHERE student_id = ?;
  `;

  db.query(query, [is_accept, student_id], (err, result) => {
    if (err) {
      console.error("Update Error:", err);
      return res.status(500).json({ error: "เกิดข้อผิดพลาดในการอัปเดตข้อมูล" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "ไม่พบข้อมูลนัดหมายสำหรับ student_id นี้" });
    }

    res.status(200).json({ message: "อัปเดตการนัดหมายสำเร็จ" });
  });
});

// Update Current Petition Status
app.post("/current_petition", (req, res) => {
  console.log("Request Headers for /current_petition:", req.headers);
  console.log("Request Body:", req.body);
  const { StudentID, PetitionName } = req.body;

  const query = `
    UPDATE studentsinfo
    SET current_petition = ?
    WHERE student_id = ?
  `;

  db.query(query, [PetitionName, StudentID], (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).send("Error updating data");
    } else {
      res.status(200).send("Data updated successfully");
    }
  });
});

const Totalcredits_storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads/TotalCredits/'); // โฟลเดอร์ที่เก็บไฟล์
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    cb(null, `${timestamp}-${file.originalname}`);
  },
});

// ตั้งค่าการอัปโหลดไฟล์
const RelatedFiles_storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "./uploads/RelatedFiles/"); // โฟลเดอร์เก็บไฟล์
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    cb(null, `${timestamp}-${file.originalname}`);
  },
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'application/pdf') {
    cb(null, true); // อนุญาตให้อัปโหลดไฟล์
  } else {
    cb(new Error('Only PDF files are allowed'), false); // ปฏิเสธไฟล์ที่ไม่ใช่ PDF
  }
};

const Totalcredits_upload = multer({
  storage:Totalcredits_storage,
  fileFilter,
});

const RelatedFiles_upload = multer({
  storage:RelatedFiles_storage,
  fileFilter,
});



//Submit REQUEST-A
app.post("/coopstudentapplication", Totalcredits_upload.single('TotalCredits_File'), (req, res) => {
  console.log("File uploaded:", req.file);
  console.log("Body data:", req.body);
  const {
    StudentID,
    FullName,
    Major,
    Year,
    Email,
    PhoneNumber,
    PetitionName,
  } = req.body;

  const totalCreditsFile = req.file ? req.file.path : null;
  console.log("Uploaded file path:", totalCreditsFile);
  

  // ตรวจสอบจำนวน Petition ของ StudentID + Petition_name
  const checkQuery = `
    SELECT COUNT(*) AS petitionCount, MAX(Petition_version) AS maxVersion
    FROM studentcoopapplication
    WHERE StudentID = ? AND Petition_name = ?;
  `;

  db.query(checkQuery, [StudentID, PetitionName], (err, results) => {

    if (err) {
      console.error("Error checking petition count:", err);
      return res.status(500).send("Failed to add petition");
    }

    const { petitionCount, maxVersion } = results[0];

    // ตรวจสอบเงื่อนไข: แต่ละคำร้องของแต่ละ StudentID จะมีไม่เกิน 10 ฉบับ
    if (petitionCount >= 10) {
      return res
        .status(400)
        .send(
          `Cannot add more than 10 versions of the petition '${Petition_name}' for this StudentID`
        );
    }

    // เพิ่ม PetitionVersion ใหม่
    const newVersion = maxVersion ? maxVersion + 1 : 1;
    console.log(newVersion)

    const query = `
      INSERT INTO StudentCoopApplication 
      (StudentID, FullName, Major, Year, Email, PhoneNumber, TotalCredits_File,Progress_State,Petition_name,Petition_version,Is_inprogress) 
      VALUES (?, ?, ?, ?, ?, ?, ? ,?, ? , ?, ?)`;

  db.query(query,[StudentID, FullName, Major, Year, Email, PhoneNumber, totalCreditsFile,0,PetitionName,newVersion,1],
    (err, result) => {
      if (err) {
        console.error('Error inserting data:', err);
        res.status(500).send('Failed to submit');
      } else {
        res.status(200).send('Submit successfully');
      }
    }
  );
  });
});

// Submit Request-B
app.post("/coopapplicationsubmit",RelatedFiles_upload.array("relatedFiles", 4),(req, res) => {
  console.log("File uploaded:", req.files);
  console.log("Body data:", req.body);
  const {
      StudentID,
      FullName,
      Major,
      Year,
      Email,
      PhoneNumber,
      CompanyNameTH,
      CompanyNameEN,
      CompanyAddress,
      CompanyProvince,
      CompanyPhoneNumber,
      PetitionName,
      Allowance,
      Coop_StartDate,
      Coop_EndDate,
    } = req.body;

    const files = req.files;

    if (!StudentID || !FullName || !Major || !Year || !Email || !PhoneNumber) {
      return res.status(400).json({ message: "กรุณากรอกข้อมูลนิสิตให้ครบถ้วน" });
    }

    if (files.length === 0) {
      return res
        .status(400)
        .json({ message: "กรุณาอัปโหลดเอกสารอย่างน้อย 1 ไฟล์" });
    }

    const filePaths = files.map((file) => file.filename).join(",");
    // ตรวจสอบจำนวน Petition ของ StudentID + Petition_name
    const checkQuery = `
      SELECT COUNT(*) AS petitionCount, MAX(Petition_version) AS maxVersion
      FROM coopapplication
      WHERE StudentID = ? AND Petition_name = ?;
    `;

    db.query(checkQuery, [StudentID, PetitionName], (err, results) => {

      if (err) {
        console.error("Error checking petition count:", err);
        return res.status(500).send("Failed to add petition");
      }

      const { petitionCount, maxVersion } = results[0];

      // ตรวจสอบเงื่อนไข: แต่ละคำร้องของแต่ละ StudentID จะมีไม่เกิน 10 ฉบับ
      if (petitionCount >= 10) {
        return res
          .status(400)
          .send(
            `Cannot add more than 10 versions of the petition '${Petition_name}' for this StudentID`
          );
      }

      // เพิ่ม PetitionVersion ใหม่
      const newVersion = maxVersion ? maxVersion + 1 : 1;
      console.log(newVersion)

      const query = `
      INSERT INTO coopapplication 
      (StudentID, FullName, Major, Year, Email, PhoneNumber, CompanyNameTH, 
      CompanyNameEN, CompanyAddress, CompanyProvince, CompanyPhoneNumber, FilePath, 
      Petition_name, Progress_State, Petition_version, Allowance, Coop_StartDate, Coop_EndDate,Is_inprogress) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)
    `;

      const values = [
        StudentID,
        FullName,
        Major,
        Year,
        Email,
        PhoneNumber,
        CompanyNameTH,
        CompanyNameEN,
        CompanyAddress,
        CompanyProvince,
        CompanyPhoneNumber,
        filePaths,
        PetitionName || "คำร้องขอปฏิบัติงานสหกิจศึกษา",
        0, // rPogress_State เริ่มต้นเป็น 0
        newVersion,
        Allowance,
        Coop_StartDate,
        Coop_EndDate,
        1
      ];

      // บันทึกข้อมูลลงใน MySQL
      db.query(query, values, (err, result) => {
        if (err) {
          console.error("Error inserting data:", err);
          return res
            .status(500)
            .json({ message: "เกิดข้อผิดพลาดในการบันทึกข้อมูล" });
        }
        res.status(200).json({ message: "บันทึกข้อมูลสำเร็จ" });
      });
  });
});

//ดึงคำร้องฌฉพาะ
app.get("/petitions/:student_id", (req, res) => {
  const {student_id} = req.params;
  const query = `
  SELECT 
      ApplicationID,
      StudentID, 
      FullName, 
      Major, 
      Year, 
      Petition_name,
      Petition_version,
      Progress_State,
      SubmissionDate
  FROM 
      studentcoopapplication
  WHERE StudentID = ?

  UNION ALL

  SELECT
      ApplicationID,
      StudentID, 
      FullName, 
      Major, 
      Year, 
      Petition_name,
      Petition_version,
      Progress_State,
      SubmissionDate
  FROM 
      coopapplication 
  WHERE StudentID = ?
  
  ORDER BY SubmissionDate DESC;
;
  `;

  db.query(query,[student_id,student_id],(err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).send("Failed to fetch data");
    } else {
      res.status(200).json(results);
    }
  });
});

//ดึงข้อมูลเฉพาะล่าสุด
app.get("/lastpetition/:student_id", (req, res) => {
  const { student_id } = req.params;

  const query = `
    SELECT 
        ApplicationID,
        StudentID, 
        FullName, 
        Major, 
        Year, 
        Petition_name,
        Petition_version,
        Progress_State,
        SubmissionDate,
        Is_inprogress
    FROM (
        SELECT 
            ApplicationID,
            StudentID, 
            FullName, 
            Major, 
            Year, 
            Petition_name,
            Petition_version,
            Progress_State,
            SubmissionDate,
            Is_inprogress
        FROM studentcoopapplication
        WHERE StudentID = ?

        UNION ALL

        SELECT
            ApplicationID,
            StudentID, 
            FullName, 
            Major, 
            Year, 
            Petition_name,
            Petition_version,
            Progress_State,
            SubmissionDate,
            Is_inprogress
        FROM coopapplication
        WHERE StudentID = ?
    ) AS combined_data
    ORDER BY SubmissionDate DESC
    LIMIT 1;
  `;

  db.query(query, [student_id, student_id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    if (result.length === 0) {
      return res.status(404).json({ error: "No data found" });
    }
    res.json(result[0]);
  });
});



//ดึงคำร้องทั้งหมด
app.get("/allpetitions", (req, res) => {
  const query = `
  SELECT 
      ApplicationID,
      StudentID, 
      FullName, 
      Major, 
      Year, 
      Petition_name,
      Petition_version,
      Progress_State,
      SubmissionDate
  FROM 
      studentcoopapplication

  UNION ALL

  SELECT
      ApplicationID,
      StudentID, 
      FullName, 
      Major, 
      Year, 
      Petition_name,
      Petition_version,
      Progress_State,
      SubmissionDate
  FROM 
      coopapplication 
  ORDER BY SubmissionDate DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).send("Failed to fetch data");
    } else {
      res.status(200).json(results);
    }
  });
});


//ดึงคำร้องขอเป็นนิสิต sort by application_id
app.get("/studentcoopapplication/:ApplicationID", (req, res) => {
  const {ApplicationID} = req.params;

  const query = `
    SELECT * FROM studentcoopapplication WHERE ApplicationID = ?
  `;

  db.query(query,[ApplicationID],(err, result) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).send("Failed to fetch data");
    } else {
      res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
    }
  });
});

app.get("/students-per-province", (req, res) => {
  const query = `
    SELECT 
      CompanyProvince AS province,
      COUNT(StudentID) AS student_count
    FROM coopapplication
    WHERE CompanyProvince IS NOT NULL
    GROUP BY CompanyProvince
    ORDER BY student_count DESC
  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).json({ error: "Failed to fetch data" });
    } else {
      // คำนวณ % ของทั้งหมดที่นี่เลย
      const total = result.reduce((sum, item) => sum + item.student_count, 0);
      const dataWithPercentage = result.map(item => ({
        ...item,
        percentage: total > 0 ? Math.round((item.student_count / total) * 100) : 0
      }));
      res.json(dataWithPercentage);
    }
  });
});


//ดึงคำร้องขอตทำงาน sort by application_id
app.get("/coopapplication/:ApplicationID", (req, res) => {
  const {ApplicationID} = req.params;

  const query = `
    SELECT * FROM coopapplication WHERE ApplicationID = ?
  `;

  db.query(query,[ApplicationID],(err, result) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).send("Failed to fetch data");
    } else {
      res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
    }
  });
});

app.delete("/studentcoopdelete/:ApplicationID", (req, res) => {
  const { ApplicationID } = req.params;

  const query = `
    DELETE FROM studentcoopapplication WHERE ApplicationID = ?
  `;

  db.query(query, [ApplicationID], (err, result) => {
    if (err) {
      console.error("Error deleting data:", err);
      res.status(500).send("Failed to delete data");
    } else {
      if (result.affectedRows > 0) {
        res.json({ message: "Deleted successfully" });
      } else {
        res.status(404).send("ApplicationID not found");
      }
    }
  });
});

app.delete("/coopapplicationdelete/:ApplicationID", (req, res) => {
  const { ApplicationID } = req.params;

  const query = `
    DELETE FROM coopapplication WHERE ApplicationID = ?
  `;

  db.query(query, [ApplicationID], (err, result) => {
    if (err) {
      console.error("Error deleting data:", err);
      res.status(500).send("Failed to delete data");
    } else {
      if (result.affectedRows > 0) {
        res.json({ message: "Deleted successfully" });
      } else {
        res.status(404).send("ApplicationID not found");
      }
    }
  });
});

//coopproj ect
// ตั้งค่าการอัปโหลดไฟล์สำหรับโปรเจกต์
const CoopProject_storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads/coopproject/'); // โฟลเดอร์ที่เก็บไฟล์
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    cb(null, `${timestamp}-${file.originalname}`); // กำหนดชื่อไฟล์
  },
});

// ตั้งค่า multer พร้อมตรวจสอบไฟล์ให้รับเฉพาะ PDF
const CoopProject_upload = multer({
  storage: CoopProject_storage,
  fileFilter, // ใช้ fileFilter ที่กำหนดไว้แล้ว
});

// API สำหรับรับข้อมูลจาก React สำหรับโปรเจกต์
app.post("/api/coopproject", CoopProject_upload.single("FilePath"), (req, res) => {
  const { student_id, ProjectTitle, ProjectDetails, Advisor, Committee1, Committee2 } = req.body;
  const filePath = req.file ? req.file.path : null; // เก็บเส้นทางไฟล์
  console.log(req.body)
  console.log(filePath)

  const sql = "INSERT INTO coopproject (student_id, ProjectTitle, ProjectDetails, Advisor, Committee1, Committee2, FilePath) VALUES (?, ?, ?, ?, ?, ?, ?)";
  const values = [student_id, ProjectTitle, ProjectDetails, Advisor, Committee1, Committee2, filePath];
  console.log(values)

  db.query(sql, values, (err, result) => {
    if (err) {
        console.error("MySQL Error: ", err);
        return res.status(500).json({ error: err });
    }
    res.json({ message: "บันทึกข้อมูลสำเร็จ" });
  });

});

//project
// API สำหรับดึงข้อมูลโปรเจกต์ตาม student_id
app.get("/coopproject/:student_id", (req, res) => {
  const { student_id } = req.params;  // รับค่า student_id จาก URL

  // คำสั่ง SQL สำหรับดึงข้อมูลจากฐานข้อมูล
  const sql = "SELECT * FROM coopproject WHERE student_id = ?";
  db.query(sql, [student_id], (err, result) => {
    if (err) {
      console.error("MySQL Error: ", err);
      return res.status(500).json({ error: err });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "ไม่พบข้อมูลโครงงานสำหรับ student_id นี้" });
    }

    res.json(result[0]);  // ส่งข้อมูลของโปรเจกต์ที่ตรงกับ student_id กลับไป
  });
});

// Express.js API endpoint สำหรับอัพเดทสถานะโปรเจค
app.put('/updateProjectStatus/:ProjectID', async (req, res) => {
  const { ProjectID } = req.params;
  const { project_state } = req.body;

  // ตรวจสอบว่า project_state มีค่าหรือไม่
  if (project_state === undefined || project_state === null) {
    return res.status(400).json({ message: 'Missing project state' });
  }

  try {
    // การใช้ SQL Query เพื่ออัปเดตสถานะ
    const query = 'UPDATE coopproject SET project_state = ? WHERE ProjectID = ?';
    const [result] = await db.promise().query(query, [project_state, ProjectID]);

    // ตรวจสอบว่ามีการอัปเดตหรือไม่
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Project not found' });
    }

    res.json({ message: 'Project status updated successfully' });
  } catch (err) {
    console.error('Error updating project status:', err);
    return res.status(500).json({ message: 'Error updating project status' });
  }
});



app.get("/allprojects", (req, res) => {
  const sql = `
    SELECT 
        c.ProjectID, 
        s.student_id AS StudentID,
        CONCAT(s.first_name, ' ', s.last_name) AS FullName,
        s.major AS Major,
        s.year AS Year,
        c.ProjectTitle,
        c.project_state
    FROM coopproject c
    JOIN studentsinfo s ON c.student_id = s.student_id
    ORDER BY c.SubmissionDate DESC;
  `;

  db.query(sql, (err, result) => {
    if (err) {
      console.error("❌ Error fetching data:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(result);
  });
});



// API สำหรับดึงรายละเอียดโปรเจคตาม ProjectID
app.get("/projectdetails/:projectId", (req, res) => {
  const { projectId } = req.params; // ดึง projectId จาก URL
  const sql = `
    SELECT
      cp.student_id, 
      cp.ProjectTitle,
      cp.ProjectDetails,
      cp.Advisor,
      cp.Committee1,
      cp.Committee2,
      cp.FilePath,
      cp.SubmissionDate,
      cp.project_state
    FROM 
      coopproject cp
    WHERE 
      cp.ProjectID = ?;
  `;

  db.query(sql, [projectId], (err, result) => {
    if (err) {
      console.error("MySQL Error:", err);
      return res.status(500).json({ error: 'มีข้อผิดพลาดในการดึงข้อมูลโปรเจค' });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "ไม่พบข้อมูลโปรเจค" });
    }

    const project = result[0];
    
    // ตรวจสอบว่า FilePath มีค่าเป็นค่าว่างหรือไม่
    if (project.FilePath) {
      // แยกชื่อไฟล์ที่คั่นด้วย ',' และจัดการกับลิงก์ไฟล์
      project.Files = project.FilePath.split(',').map(file => `/uploads/${file.trim()}`);
    } else {
      project.Files = []; // ถ้าไม่มีไฟล์
    }
    res.json(project);
  });
});



app.get('/evaluations/:studentID/:type/:version', (req, res) => {
  const { studentID, type ,version} = req.params;
  console.log(studentID,type)
  // สร้างคำสั่ง SQL เพื่อดึงข้อมูล evaluation
  const sql = `
    SELECT * FROM evaluations
    WHERE student_id = ? AND evaluation_type = ? AND evaluation_version = ?
  `;

  // ทำการ query ข้อมูล
  db.query(sql, [studentID, type,version], (err, results) => {
    if (err) {
      console.error('Error fetching evaluation data:', err);
      return res.status(500).json({ error: 'Failed to fetch evaluation data' });
    }

    if (results.length > 0) {
      // ส่งข้อมูล evaluation กลับไป
      res.status(200).json(results[0]);
    } else {
      // หากไม่พบข้อมูล
      res.status(404).json({ message: 'Evaluation not found' });
    }
  });
});


app.get('/checkEvaluation/:studentID/:type/:version', async (req, res) => {
  const { studentID, type, version } = req.params;
  
  if (!studentID || !type || !version) {
    return res.status(400).json({ 
      success: false,
      error: 'Missing required parameters: studentID, type, or version' 
    });
  }

  const validTypes = ['supervision', 'coop_project', 'self_evaluate', 'coop_report'];
  const validVersions = ['first', 'second', 'last'];
  
  if (!validTypes.includes(type)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid evaluation type',
      validTypes: validTypes
    });
  }

  if (!validVersions.includes(version)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid evaluation version',
      validVersions: validVersions
    });
  }

  try {
    const sql = `
      SELECT * FROM evaluations
      WHERE student_id = ? AND evaluation_type = ? AND evaluation_version = ?
      LIMIT 1
    `;

    const [results] = await db.promise().query(sql, [studentID, type, version]);

    if (results.length > 0) {
      res.status(200).json({
        success: true,
        exists: true,
        data: results[0]
      });
    } else {
      res.status(200).json({ 
        success: true,
        exists: false,
        message: 'No evaluation found with the specified criteria'
      });
    }

  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({
      success: false,
      error: 'Database operation failed',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// API สำหรับดึงข้อมูลคะแนนโดยใช้ evaluationID
app.get('/evaluation_scores/:evaluationID', (req, res) => {
  const { evaluationID } = req.params;
  console.log(evaluationID)

  // สร้างคำสั่ง SQL เพื่อดึงข้อมูลคะแนน
  const sql = `
    SELECT * FROM evaluation_scores
    WHERE evaluation_id = ?
  `;

  // ทำการ query ข้อมูล
  db.query(sql, [evaluationID], (err, results) => {
    if (err) {
      console.error('Error fetching evaluation scores:', err);
      return res.status(500).json({ error: 'Failed to fetch evaluation scores' });
    }

    if (results.length > 0) {
      // ส่งข้อมูลคะแนนกลับไป
      res.status(200).json(results);
    } else {
      // หากไม่พบข้อมูล
      res.status(404).json({ message: 'No scores found for this evaluation' });
    }
  });
});

// API สำหรับดึงข้อมูลคะแนนโดยใช้ evaluationID
app.get('/evaluation_scores_bytype/:type', (req, res) => {
  const { type } = req.params;
  console.log(type)

  // สร้างคำสั่ง SQL เพื่อดึงข้อมูลคะแนน
  const sql = `
      SELECT 
        es.score_id,
        es.evaluation_id,
        es.criteria_id,
        es.score,
        es.comments,
        es.evaluation_type,
        ec.section_id,
        ec.criteria_text
      FROM evaluation_scores es
      JOIN evaluation_criteria ec ON es.criteria_id = ec.criteria_id
      WHERE es.evaluation_type = ?
      ORDER BY es.criteria_id ASC
  `;

  // ทำการ query ข้อมูล
  db.query(sql, [type], (err, results) => {
    if (err) {
      console.error('Error fetching evaluation scores:', err);
      return res.status(500).json({ error: 'Failed to fetch evaluation scores' });
    }

    if (results.length > 0) {
      // ส่งข้อมูลคะแนนกลับไป
      res.status(200).json(results);
    } else {
      // หากไม่พบข้อมูล
      res.status(404).json({ message: 'No scores found for this evaluation' });
    }
  });
});



// API เพื่อดึงข้อมูล criteria ทั้งหมด
app.get('/criteria/all', async (req, res) => {
  try {
    // ดึง connection จาก pool
    const connection = await pool.getConnection();
    
    // คำสั่ง SQL เพื่อดึงข้อมูล criteria ทั้งหมด
    const [rows] = await connection.query(`
      SELECT 
        criteria_id,
        section_id,
        criteria_text,
        created_at,
        updated_at
      FROM evaluation_criteria
      ORDER BY section_id, criteria_id
    `);
    
    // คืน connection
    connection.release();
    
    // ส่งข้อมูลกลับเป็น JSON
    res.status(200).json(rows);
    
  } catch (error) {
    console.error('Error fetching criteria:', error);
    res.status(500).json({ 
      error: 'Failed to fetch criteria',
      details: error.message 
    });
  }
});


// ดึงหัวข้อหลักทั้งหมด
app.get('/selfEvaluation_sections', (req, res) => {
  const sql = 'SELECT * FROM evaluation_sections WHERE section_type = ?';
  db.query(sql,["self_evaluate"], (err, results) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Database query failed' });
      }
      res.json(results);
  });
});

// ดึงหัวข้อหลักทั้งหมดและแปลงชื่อเป็นภาษาอังกฤษ
app.get('/selfEvaluation_sections_ForChart', (req, res) => {
  const sql = `
    SELECT 
      section_id,
      CASE 
        WHEN section_name = 'ความประพฤติของนิสิต' THEN 'Behavior'
        WHEN section_name = 'การพัฒนาตนเอง' THEN 'Self Development'
        WHEN section_name = 'การแสดงความมีส่วนร่วมกับองค์กร' THEN 'Participation'
        WHEN section_name = 'ความรู้และความสามารถพี้นฐาน' THEN 'Knowledge'
        WHEN section_name = 'ความพึงพอใจของนิสิต' THEN 'Satisfaction'
        WHEN section_name = 'การจัดทำรายงาน' THEN 'Work Report'
        WHEN section_name = 'สรุปโดยรวมของนิสิต' THEN 'Overall'
        ELSE section_name
      END AS section_name,
      section_type
    FROM evaluation_sections 
    WHERE section_id IN (12,13,14,15,16,17,18)
  `;
  db.query(sql, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database query failed' });
    }
    res.json(results);
  });
});

// ดึงหัวข้อหลักทั้งหมด
app.get('/firstsupervision_sections', (req, res) => {
  const sql = 'SELECT * FROM evaluation_sections WHERE section_id IN (1,2,3,4,5,6)';
  db.query(sql, (err, results) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Database query failed' });
      }
      res.json(results);
  });
});

// ดึงหัวข้อหลักทั้งหมด
app.get('/secondsupervision_sections', (req, res) => {
  const sql = 'SELECT * FROM evaluation_sections WHERE section_id IN (1,2,3,7,5,6)';
  db.query(sql, (err, results) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Database query failed' });
      }
      res.json(results);
  });
});

// ดึงหัวข้อหลักทั้งหมด
app.get('/projectevaluation_sections', (req, res) => {
  const sql = 'SELECT * FROM evaluation_sections WHERE section_id IN (8,9,10,11)';
  db.query(sql, (err, results) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Database query failed' });
      }
      res.json(results);
  });
});


// ดึงหัวข้อหลักทั้งหมด
app.get('/reportevaluation_sections', (req, res) => {
  const sql = 'SELECT * FROM evaluation_sections WHERE section_id IN (19)';
  db.query(sql, (err, results) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Database query failed' });
      }
      res.json(results);
  });
});

// ดึงหัวข้อย่อยของแต่ละหัวข้อหลัก
app.get('/criteria/:section_id', (req, res) => {
  const { section_id } = req.params;
  const sql = 'SELECT * FROM evaluation_criteria WHERE section_id = ?';
  db.query(sql, [section_id], (err, results) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Database query failed' });
      }
      res.json(results);
  });
});

app.post("/addevaluation", (req, res) => {
  console.log(req.body)
  const { student_id, company_id, evaluator_name, evaluate_by, evaluation_version, evaluation_for, evaluation_type } = req.body;
  if (!student_id || !company_id || !evaluator_name || !evaluate_by || !evaluation_version || !evaluation_for || !evaluation_type) {
      return res.status(400).json({ message: "Missing required fields" });
  }

  const query = `
      INSERT INTO evaluations 
      (student_id, company_id, evaluator_name, created_at, evaluate_by, evaluation_version, evaluation_for, evaluation_type) 
      VALUES (?, ?, ?, NOW(), ?, ?, ?, ?)
  `;

  db.query(
      query,
      [student_id, company_id, evaluator_name, evaluate_by, evaluation_version, evaluation_for, evaluation_type],
      (err, result) => {
          if (err) {
              console.error(err);
              return res.status(500).json({ message: "Error inserting data", error: err });
          }
          res.status(201).json({ message: "Evaluation added successfully", evaluation_id: result.insertId });
      }
  );
});

app.post("/addcoopreport", (req, res) => {
  console.log(req.body)
  const { evaluation_id, student_id, report_title_th, report_title_eng, additional_comments} = req.body;
  if (!evaluation_id || !student_id || !report_title_th || !report_title_eng || !additional_comments) {
      return res.status(400).json({ message: "Missing required fields" });
  }

  const query = `
      INSERT INTO coop_report 
      (evaluation_id, student_id, report_title_th,report_title_eng,additional_comments, created_at) 
      VALUES (?, ?, ?, ?, ?, NOW())
  `;

  db.query(
      query,
      [evaluation_id, student_id, report_title_th, report_title_eng, additional_comments],
      (err, result) => {
          if (err) {
              console.error(err);
              return res.status(500).json({ message: "Error inserting data", error: err });
          }
          res.status(201).json({ message: "Evaluation added successfully", evaluation_id: result.insertId });
      }
  );
});



app.put('/updateEvaluatedState/:evaluation_id', async (req, res) => {
  const { evaluationID } = req.params;
  const query = 'UPDATE evaluations SET is_evaluated = ? WHERE evaluation_id = ?';
  db.query(query, [1,evaluationID], (err, results) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Database query failed' });
      }
      res.json(results);
  });
});


app.post('/evaluation_scores', (req, res) => {
  const scores = req.body.scores;
  console.log(scores)
  if (!scores || !Array.isArray(scores)) {
    return res.status(400).json({ error: 'Invalid data format' });
  }

  // สร้างคำสั่ง SQL สำหรับเพิ่มข้อมูล
  const sql = 'INSERT INTO evaluation_scores (evaluation_id, criteria_id,section_id, score, evaluation_type, comments) VALUES ?';
  const values = scores.map((score) => [
    score.evaluation_id,
    score.criteria_id,
    score.section_id,
    score.score,
    score.evaluation_type,
    score.comments || null, // หากไม่มี comments ให้ใช้ null
  ]);

  // ทำการบันทึกข้อมูล
  db.query(sql, [values], (err, result) => {
    if (err) {
      console.error('Error inserting data:', err);
      return res.status(500).json({ error: 'Failed to insert data' });
    }

    console.log('Data inserted successfully:', result);
    res.status(200).json({ message: 'Data inserted successfully' });
  });
});

// ใน backend (ตัวอย่างใช้ Express.js)
app.get('/checkEvaluation/', async (req, res) => {
  const { student_id, evaluation_type } = req.query;
  
  try {
    const evaluation = await Evaluation.findOne({ 
      where: { 
        student_id, 
        evaluation_type 
      } 
    });
    
    res.json({ exists: !!evaluation });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start Server
app.listen(5000, () => {
  console.log('Server is running on http://localhost:5000');  
});