# 🔐 Authentication Microservice (FastAPI + PostgreSQL + Redis + Docker)

A robust authentication service built with **FastAPI**, **PostgreSQL**, **Redis**, and **Docker**. Includes user registration, login with JWT access & refresh tokens, session management, token blacklisting, and login history tracking.

---

## 🚀 Features

- User registration & login with email/password  
- JWT authentication (Access & Refresh tokens)  
- Redis-based refresh token blacklisting  
- Secure password hashing (bcrypt)  
- Login history tracking (IP, User-Agent, Timestamp)  
- Modular FastAPI structure with Alembic migrations  
- Dockerized PostgreSQL & Redis  
- Ready for CI/CD & AWS deployment  

---

## 🧱 Tech Stack

- 🐍 FastAPI  
- 🐘 PostgreSQL  
- 🐳 Docker & Docker Compose  
- 🧠 Redis  
- 🛡️ JWT (python-jose)  
- 🔒 bcrypt (via PassLib)  
- 📦 SQLAlchemy + Alembic  
- ⚙️ GitHub Actions (CI/CD ready)  

---

## 📦 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/your-username/auth-microservice.git
cd auth-microservice
```

### 2. Create `.env` file 
Follow `.env.example` file to add Environment Variables.


### 3. Build and run with Docker
```bash
docker-compose up --build
```

API will be available at: http://localhost:8000


## 🔍 API Endpoints
- 🔸 POST /auth/register

Register a new user with email and password.

- 🔸 POST /auth/login

Login and receive access + refresh tokens.

- 🔸 POST /auth/refresh

Get a new access token using a valid refresh token (sent in headers).

- 🔸 POST /auth/logout

Blacklist the refresh token to force logout.

- 🔸 GET /users/me

Fetch current user's information using bearer token.

- 🔸 GET /users/login-history

View user's login history (IP address, user agent, timestamp).


## 🧪 Testing
You can use:

- Postman
- cURL
- Or simple browser for redirection

## 📌 Possible Feature Improvements
- Email verification via OTP
- Password reset via email
- Rate limiting (per IP/token)
- Admin interface for user management
- Optional 2FA/MFA integration

## 👨‍💻 Author
Built with ❤️ by [Irfan Ahmad](!https://github.com/irfan-ahmad-byte)