# 🛡️ Enterprise Ready Authentication Backend

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
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