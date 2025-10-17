Passport.js Local + JWT Authentication

This project demonstrates a complete authentication system using Passport.js (Local Strategy) along with JWT (Access & Refresh Tokens).
It supports:

Signup and Login using username & password

JWT Access and Refresh Token handling

Protected routes using token verification

User session management with Passport

🚀 Features

Signup & Login (Local Strategy)

Password Hashing using bcrypt

JWT Authentication (Access & Refresh Tokens)

Token Refresh Route for expired access tokens

Session Management with express-session

Protected Route with token verification

MongoDB Integration using Mongoose

🧰 Technologies Used

Node.js

Express.js

MongoDB + Mongoose

Passport.js (Local Strategy)

JSON Web Tokens (JWT)

bcrypt for password hashing

dotenv for environment variables

⚙️ Installation Steps

Clone the Repository

git clone https://github.com/M-haxan/Passport_js.git
cd Passport_js


Install Dependencies

npm install


Create .env File
In the project root directory, create a new file named .env and add the following:

JWT_SECRET=your_jwt_secret_key_here
JWT_REFRESH_SECRET=your_refresh_secret_key_here


⚠️ Note: Never commit your .env file to GitHub. It contains sensitive keys.

Start MongoDB
Make sure MongoDB is running locally on port 27017 (default).

Run the Server

node index.js


Server Running

🚀 Server running on http://localhost:3000

📡 API Endpoints
1️⃣ Signup

POST /signup
Creates a new user.
Body:

{
  "username": "testuser",
  "password": "123456"
}

2️⃣ Login

POST /login
Logs in user using Passport Local Strategy and returns JWT tokens.
Body:

{
  "username": "testuser",
  "password": "123456"
}


Response:

{
  "message": "Login successful!",
  "username": "testuser",
  "accessToken": "jwt_access_token_here",
  "refreshToken": "jwt_refresh_token_here"
}

3️⃣ Refresh Token

POST /refresh
Generates new Access Token using Refresh Token.
Body:

{
  "token": "your_refresh_token_here"
}

4️⃣ Logout

POST /logout
Removes refresh token from active list.
Body:

{
  "token": "your_refresh_token_here"
}

5️⃣ Protected Route

GET /protected
Requires valid Access Token.
Header:

Authorization: Bearer <access_token>


Response:

{
  "message": "Access granted to protected route ✅",
  "user": {
    "id": "...",
    "username": "testuser",
    "iat": ...,
    "exp": ...
  }
}

📁 Project Structure
Passport_js/
│
├── models/
│   └── user.js           # Mongoose User Schema
│
├── .env                  # Environment variables (not uploaded)
├── index.js              # Main Express app
├── package.json
└── README.md

🧠 Notes

Keep .env file private and never push it to GitHub.

You can share the .env values privately with your sir (for example via WhatsApp or email).

If the repo accidentally included .env, remove it using:

git rm --cached .env
echo ".env" >> .gitignore
git add .gitignore
git commit -m "Remove .env from repo"
git push origin main

👨‍💻 Author

Muhammad Hassan
📧 Email: your_email@example.com

🔗 GitHub: M-haxan
