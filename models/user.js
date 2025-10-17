// // models/user.js
// const mongoose = require("mongoose");
// const passportLocalMongoose = require("passport-local-mongoose");

// // 1️⃣ Create User Schema
// const userSchema = new mongoose.Schema({
//   username: String,
//   email: String
//   // Password field auto handle karega passport-local-mongoose
// });

// // 2️⃣ Add Plugin (it automatically adds hash + salt fields)
// //userSchema.plugin(passportLocalMongoose);

// // 3️⃣ Export Model
// module.exports = mongoose.model("User", userSchema);

// models/user.js
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  
  username: String,
  email: String,
  password: String,
  googleId: String, // for Google OAuth
});

module.exports = mongoose.model("User", userSchema);
