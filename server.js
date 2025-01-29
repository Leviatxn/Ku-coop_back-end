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

// API ดึงข้อมูล Info
app.get("/user_info/:student_id", (req, res) => {
  const { student_id } = req.params;

  const query = `
    SELECT 
      first_name, 
      last_name, 
      student_id, 
      major, 
      year, 
      email, 
      phone_number, 
      digital_id, 
      current_petition, 
      lastest_coopapplication, 
      lastest_studentcoopapplication, 
      current_state
    FROM studentsinfo
    WHERE student_id = ?`;

  db.query(query, [student_id], (err, result) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (result.length === 0) return res.status(404).json({ error: "User not found" });

    res.json(result[0]); // ส่งข้อมูลผู้ใช้กลับ
  });
});

//Post Info
app.post("/studentsinfo", (req, res) => {
  const { first_name, last_name, student_id, major, year, email, phone_number } = req.body;

  const query = `
    INSERT INTO studentsinfo (first_name, last_name, student_id, major, year, email, phone_number)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [first_name, last_name, student_id, major, year, email, phone_number],
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
      (StudentID, FullName, Major, Year, Email, PhoneNumber, TotalCredits_File,Progress_State,Petition_name,Petition_version) 
      VALUES (?, ?, ?, ?, ?, ?, ? ,?, ? , ?)`;

  db.query(query,[StudentID, FullName, Major, Year, Email, PhoneNumber, totalCreditsFile,0,PetitionName,newVersion],
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
        INSERT INTO coopapplication (
          StudentID, FullName, Major, Year, Email, PhoneNumber,
          CompanyNameTH, CompanyNameEN, CompanyAddress, CompanyProvince, 
          CompanyPhoneNumber, FilePath, Petition_name, Progress_State,Petition_version
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

//ดึงคำร้องทั้งหมด
app.get("/allpetitions", (req, res) => {
  const query = `
  SELECT 
      StudentID, 
      FullName, 
      Major, 
      Year, 
      Petition_name,
      Petition_version
  FROM 
      studentcoopapplication

  UNION ALL

  SELECT 
      StudentID, 
      FullName, 
      Major, 
      Year, 
      Petition_name,
      Petition_version
  FROM 
      coopapplication 
  ORDER BY StudentID;
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


// Start Server
app.listen(5000, () => {
  console.log('Server is running on http://localhost:5000');
});