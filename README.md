Passport JWT Authentication App

A simple Node.js + Express authentication system using Passport.js, JWT (Access & Refresh Tokens), and MongoDB.

🚀 Features

User signup and login with hashed passwords (bcrypt)

Local authentication using Passport.js

JWT-based access & refresh token handling

Protected routes using access tokens

Logout and token refresh support

MongoDB integration with Mongoose

/// Note///



📡 API Routes
Method	Route	Description
POST	/signup	Create a new user
POST	/login	Login user & return tokens
POST	/refresh	Get new access token
POST	/logout	Logout and invalidate token
GET	/protected	Access protected route (requires JWT)

