// models/user.js
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  
  username: String,
  email: String,
  password: String,
  googleId: String, // for Google OAuth
});

module.exports = mongoose.model("User", userSchema);
