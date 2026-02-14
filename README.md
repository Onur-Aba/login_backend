# 🛡️ Enterprise Ready Authentication Backend

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://raw.githubusercontent.com/nestjs/nest/master/docs/assets/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

<p align="center">
  A production-ready, highly secure, and scalable Authentication Microservice built with <strong>NestJS</strong>.
  <br />
  Designed with "Security First" principles, implementing industry-standard practices like <strong>2FA, Rate Limiting, Session Management, and Audit Logging</strong>.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/NestJS-E0234E?style=for-the-badge&logo=nestjs&logoColor=white" alt="NestJS" />
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/TypeORM-FE0C05?style=for-the-badge&logo=typeorm&logoColor=white" alt="TypeORM" />
  <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
</p>

---

## 🚀 Key Features

This project goes beyond simple login/register. It includes advanced security and architectural patterns:

- **🔐 Advanced Authentication:**
  - JWT Access & Refresh Token Rotation.
  - **Reuse Detection:** Prevents token theft by revoking compromised token families.
  - **2FA (Two-Factor Auth):** Email-based OTP (One Time Password) with time-sensitive validity.
  - **Session Management:** View and revoke active sessions (device info, IP, browser) remotely.

- **🛡️ Hardened Security:**
  - **Rate Limiting (Throttler):** Brute-force protection for login/register endpoints.
  - **Google reCAPTCHA v3:** Invisible bot protection scoring.
  - **Helmet & HPP:** Protection against HTTP Parameter Pollution and common headers.
  - **CORS Config:** Strict origin policies for production environments.

- **📨 Reliable Messaging:**
  - **Transactional Outbox Pattern:** Guarantees email delivery even if the mail service is down (Dual-Write problem solved).
  - **Email Verification:** Secure hashing mechanism for account activation.

- **🏗️ Architecture & Quality:**
  - **Modular Monolith:** Clean separation of concerns (Auth, User, Outbox, Audit).
  - **Health Checks:** Native Kubernetes/Docker health probes.
  - **Swagger OpenAPI:** Auto-generated API documentation.
  - **Compression:** Gzip compression for high performance.

---

## 🛠️ Installation & Setup

### 1. Prerequisites
Ensure you have the following installed:
- [Node.js](https://nodejs.org/) (v18 or higher)
- [PostgreSQL](https://www.postgresql.org/) (or use Docker)
- [npm](https://www.npmjs.com/)

### 2. Clone the Repository
```bash
git clone [https://github.com/onur-aba/login_backend.git](https://github.com/onur-aba/login_backend.git)
cd login_backend
```

### 3. Install Dependencies
```bash
npm install
```

### 4. Environment Configuration (.env)
Create a `.env` file in the root directory. You can copy the example below:

```bash
# --- APP CONFIG ---
NODE_ENV=development
PORT=3000
# Frontend URL for CORS (In production, use real domain)
FRONTEND_URL=http://localhost:5173

# --- DATABASE CONNECTION (PostgreSQL) ---
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=mysecretpassword
DB_NAME=auth_db
DB_SYNC=true  # Set 'false' in production!

# --- JWT SECURITY (Critical) ---
# Generate new keys using: openssl rand -hex 64
JWT_SECRET=YOUR_SUPER_SECRET_LONG_KEY_HERE
JWT_EXPIRATION=15m
JWT_REFRESH_SECRET=YOUR_SUPER_SECRET_REFRESH_KEY_HERE
JWT_REFRESH_EXPIRATION=7d

# --- GOOGLE RECAPTCHA v3 ---
# Get keys from: [https://www.google.com/recaptcha/admin](https://www.google.com/recaptcha/admin)
RECAPTCHA_SECRET_KEY=YOUR_GOOGLE_SECRET_KEY
```

## 🏃‍♂️ Running the Application

### Development Mode
```bash
npm run start:dev
```
The server will start at `http://localhost:3000`.

### Production Mode
```bash
npm run build
npm run start:prod
```

### 🐳 Running with Docker (Optional)
If you have Docker installed, you can start the database immediately:
```bash
docker-compose up -d
```

## 📚 API Documentation (Swagger)
Once the application is running, you can access the interactive API documentation.
This interface allows you to test endpoints directly from the browser.

👉 **URL:** `http://localhost:3000/api/docs`

## 🧪 Testing
The project includes E2E (End-to-End) testing setup.

```bash
# Run e2e tests
npm run test:e2e

# Run unit tests
npm run test
```

## 🤝 Contact & Feedback

If you encounter any issues running the project, have suggestions for refactoring, or want to contribute to this open-source initiative:

📧 **Email:** [onuraba34@gmail.com](mailto:onuraba34@gmail.com)

---
*Developed by Onur Aba.*