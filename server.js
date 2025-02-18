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

app.use("/uploads", express.static(path.join(__dirname)));


// Enable CORS
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

// ตั้งค่าการเชื่อมต่อกับฐานข้อมูล
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
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
          const token = jwt.sign({ studentId: user.student_id }, "secret_key", { expiresIn: "1h" });
            
          // ✅ เก็บ Token ใน Session
          req.session.token = token;
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

//Admin Login
app.post("/admin-login", (req, res) => {
  console.log(req.body)

  const { email, password } = req.body;

  const query = "SELECT * FROM users WHERE email = ?";
  db.query(query, [email], (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.length === 0) return res.status(404).json({ error: "User not found" });

      const user = result[0];
      console.log(user)
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) return res.status(500).json({ error: "Error comparing passwords" });
          if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

          const token = jwt.sign({ email: user.email }, "secret_key", { expiresIn: "1h" });
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



//API ดึงข้อมูล user Sort by role
app.get("/studentsinfo", (req, res) => {

  const query = "SELECT first_name, last_name, student_id, major, year, phone_number,is_coopstudent,company_name  FROM studentsinfo ";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).send("Failed to fetch data");
    } else {
      res.status(200).json(results);
    }
  });
});

//Post Info
app.post("/addstudentsinfo", (req, res) => {
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
  
  ORDER BY Petition_version DESC;
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
        SubmissionDate
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
            SubmissionDate
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
            SubmissionDate
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

// Start Server
app.listen(5000, () => {
  console.log('Server is running on http://localhost:5000');
});