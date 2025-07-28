# User Management System

## Quick Setup

```bash
# Backend
Backend Setup
Clone the repository
bashgit clone <repository-url>
cd user-management-system/backend

Install dependencies
bashnpm install

Environment Variables
Create a .env file in the backend directory:
envPORT=3000
JWT_SECRET=QA_JSONWEBTOKEN
NODE_ENV=development

Start the server
bashnpm start
The API will be available at http://localhost:3000


This is a secure and modular Express.js API server with JWT-based authentication, role-based access control, and user management features.
It includes middleware for validation, rate limiting, CORS, helmet security, and exposes endpoints for login, user CRUD, and statistics.


Authentication & Authorization: JWT-based authentication with role-based access control
User Management: Complete CRUD operations for user accounts
Security: Rate limiting, input validation, password hashing with bcrypt
Statistics: Dashboard analytics and user statistics
Data Validation: Comprehensive validation using express-validator
Error Handling: Centralized error handling with detailed responses

Node.js - Runtime environment
Express.js - Web framework
bcryptjs - Password hashing
jsonwebtoken - JWT authentication
express-validator - Input validation
express-rate-limit - Rate limiting
helmet - Security headers
cors - Cross-origin resource sharing

# Frontend
git clone frontend file or install repo zip file
npm install && npm run dev
```

## Test Credentials for login

- Email: `ali@example.com`
- Password: `password`

## Features

- ✅ Login/Logout
- ✅ Create User
- ✅ Edit User
- ✅ Delete User
- ✅ Search & Filter Users
- ✅ User Statistics
