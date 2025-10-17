// ========================== IMPORTS ==========================
require("dotenv").config(); // Load environment variables from .env
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("./models/user"); // Import User Model
const app = express();
//console.log("JWT Secret:", process.env.JWT_SECRET);

app.use((req, res, next) => {
  console.log("Request Content-Type:", req.headers["content-type"]);
  next();
});

// ========================== MIDDLEWARE ==========================
app.use(express.json()); // For JSON payloads
app.use(express.urlencoded({ extended: true }));

// ========================== DATABASE CONNECT ==========================
mongoose
  .connect("mongodb://127.0.0.1:27017/passportJwtDemo")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ DB Error:", err));

// ========================== SESSION CONFIG ==========================
app.use(
  session({
    secret: "thisissecret",
    resave: false,
    saveUninitialized: false,
  })
);

// ========================== PASSPORT CONFIG ==========================
app.use(passport.initialize());
app.use(passport.session());

// Local Strategy (username/password based)
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      console.log("Login Attempt →", username);

      const user = await User.findOne({ username });
      if (!user) return done(null, false, { message: "User not found" });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch)
        return done(null, false, { message: "Incorrect password" });

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// Serialize user to session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ========================== JWT TOKEN FUNCTIONS ==========================

// Generate Access Token (Short Expiry)
function generateAccessToken(user) {
  return jwt.sign(
    { id: user._id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "3m" } // 3 minutes expiry
  );
}

// Generate Refresh Token (Long Expiry)
function generateRefreshToken(user) {
  return jwt.sign(
    { id: user._id, username: user.username },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" } // 7 days expiry
  );
}

// Temporary store for refresh tokens (can use Redis or DB in real app)
let refreshTokens = [];

// ========================== ROUTES ==========================

// -------- SIGNUP ROUTE --------
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username and password are required" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      username,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: "User created successfully", newUser });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ message: "Error creating user" });
  }
});

// -------- LOGIN ROUTE (Local Auth + JWT Generation) --------
app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    // login() will create session for user
    req.logIn(user, (err) => {
      if (err) return next(err);

      // Generate Tokens
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);

      // Store refresh token temporarily
      refreshTokens.push(refreshToken);

      res.json({
        message: "Login successful!",
        username: user.username,
        accessToken,
        refreshToken,
      });
    });
  })(req, res, next);
});

// -------- REFRESH TOKEN ROUTE --------
app.post("/refresh", (req, res) => {
  
  console.log("🔹 Body received:", req.body);
  
  

if (!req.body || !req.body.token) {
    return res.status(400).json({ message: "Request body or token missing" });
  }
  const { token } = req.body;
  if (!token)
    return res.status(401).json({ message: "Refresh token required" });
  if (!refreshTokens.includes(token))
    return res.status(403).json({ message: "Invalid refresh token" });

  try {
    const user = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const newAccessToken = generateAccessToken(user);
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).json({ message: "Invalid or expired refresh token" });
  }
});

// -------- LOGOUT ROUTE --------
app.post("/logout", (req, res) => {
  const { token } = req.body;
  refreshTokens = refreshTokens.filter((t) => t !== token);
  req.logout(() => {});
  res.json({ message: "Logged out successfully!" });
});

// -------- ACCESS TOKEN VERIFICATION MIDDLEWARE --------
function verifyAccessToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>

  if (!token) return res.status(401).json({ message: "Access token required" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or expired access token" });
  }
}

// -------- PROTECTED ROUTE --------
app.get("/protected", verifyAccessToken, (req, res) => {
  res.json({
    message: "Access granted to protected route ✅",
    user: req.user,
  });
});
app.post("/test", (req, res) => {
  console.log("Body received:", req.body);
  res.json(req.body);
});

// ========================== START SERVER ==========================
app.listen(3000, () => {
  console.log("🚀 Server running on http://localhost:3000");
});
