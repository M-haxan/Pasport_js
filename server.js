// server.js (corrected)

// ========================== IMPORTS ==========================
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("./models/user");
const Token = require("./models/token");

const app = express();

// ========================== MIDDLEWARE ==========================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// debug header
app.use((req, res, next) => {
  console.log("Request Content-Type:", req.headers["content-type"]);
  next();
});

// ========================== DB ==========================
mongoose
  .connect(process.env.MONGO_URL || "mongodb://127.0.0.1:27017/passportJwtDemo")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ DB Error:", err));

// ========================== SESSIONS & PASSPORT ==========================
app.use(
  session({
    secret: process.env.SESSION_SECRET || "thisissecret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// --------------------------- Passport Local Strategy ---------------------------
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username }); // use username consistently
      if (!user) return done(null, false, { message: "User not found" });
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return done(null, false, { message: "Incorrect password" });
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ========================== JWT HELPERS (consistent names) ==========================
const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET || process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || process.env.JWT_REFRESH_SECRET;

function generateAccessToken(payload) {
  // payload should be { id, username } or similar
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: "3m" });
}

function generateRefreshToken(payload) {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: "7d" });
}

// ========================== ROUTES ==========================

// Signup (stores username + hashed password)
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: "Username and password required" });

    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashed });
    await newUser.save();
    res.status(201).json({ message: "User created", user: { id: newUser._id, username: newUser.username } });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ message: "Error creating user" });
  }
});

// Login — issues access & refresh tokens and stores refresh token in DB
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    // keep same field names as signup (username)
    if (!username || !password) return res.status(400).json({ message: "Username and password required" });

    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: "Invalid password" });

    const payload = { id: user._id.toString(), username: user.username };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    // Save refresh token to DB
    await Token.create({ token: refreshToken });

    res.json({ message: "Login successful", accessToken, refreshToken });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Refresh route — check DB then verify and return new access token
app.post("/refresh", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(401).json({ message: "Refresh token required" });

    // check DB
    const stored = await Token.findOne({ token });
    if (!stored) return res.status(403).json({ message: "Invalid refresh token" });

    // verify signature/expiry
    const decoded = jwt.verify(token, REFRESH_SECRET); // will throw if invalid/expired
    const payload = { id: decoded.id, username: decoded.username };
    const newAccessToken = generateAccessToken(payload);

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    console.error("Refresh Error:", err.message);
    return res.status(403).json({ message: "Invalid or expired refresh token" });
  }
});

// Logout — remove refresh token from DB
app.post("/logout", async (req, res) => {
  try {
    const { token } = req.body;
    if (token) {
      await Token.deleteOne({ token });
    }
    // also log out passport session if present
    req.logout(() => {});
    res.json({ message: "Logged out" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// verify access token middleware (uses same ACCESS_SECRET)
function verifyAccessToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access token required" });

  jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid or expired access token" });
    req.user = decoded;
    next();
  });
}

// protected route
app.get("/protected", verifyAccessToken, (req, res) => {
  res.json({ message: "Access granted", user: req.user });
});

// test route
app.post("/test", (req, res) => {
  console.log("Body received:", req.body);
  res.json(req.body);
});

app.listen(3000, () => console.log("🚀 Server running on http://localhost:3000"));
