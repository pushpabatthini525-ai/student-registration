# Student Registration (Node.js + MySQL)

Student registration system with email notifications, student login, forgot/reset
password, bcrypt password hashing, and role-based access (Student vs Admin).

## Features
- Registration form (name, DOB, parents, mobiles, place, email)
- One registration per email (enforced by the database)
- Auto-generated Registration Number and Password
- **Email notifications**: registration confirmation, approval, rejection
- **Student login** (Registration Number + Password) to view live status
- **Forgot / Reset Password** via emailed link (expires in 30 minutes)
- **Bcrypt** password hashing (old accounts are auto-upgraded on next login)
- **Role-based access**: separate Admin and Student logins/sessions
- Admin: full list, search, filter, Approve / Reject with reason
- Public page shows only count and masked names (privacy)

## Requirements
- Node.js (LTS)
- MySQL (running)
- A Gmail account (for sending emails) — optional, see below

## Setup

1. Open this folder in VS Code, open a terminal, run:
   ```
   npm install
   ```
2. Copy `.env.example`, rename the copy to `.env`.
3. Fill in `.env`:
   - `DB_PASSWORD` — your MySQL password
   - `ADMIN_USER` / `ADMIN_PASSWORD` — your chosen admin login
   - `SESSION_SECRET` — any long random text
   - `EMAIL_USER` / `EMAIL_PASS` — see "Enabling email" below
4. Run:
   ```
   npm start
   ```
5. Open http://localhost:3000

If `EMAIL_USER` / `EMAIL_PASS` are left blank, the app still works —
emails are just skipped (logged to the terminal instead of sent).

## Enabling email (Gmail App Password)

Gmail does not accept your normal password for apps like this one. You need
a 16-character **App Password**:

1. Go to https://myaccount.google.com/security
2. Turn on **2-Step Verification** if it isn't already on.
3. Go to https://myaccount.google.com/apppasswords
4. Create an app password (name it anything, e.g. "Student Registration").
5. Copy the 16-character code shown.
6. In `.env`:
   ```
   EMAIL_USER=youraddress@gmail.com
   EMAIL_PASS=the16charactercode
   ```
   (paste it without spaces)
7. Restart the server (`npm start`).

## Pages
- `/index.html` — registration form
- `/success.html` — shown right after registering
- `/student-login.html` — student login (Reg No + Password)
- `/student-dashboard.html` — student's own status
- `/forgot-password.html` — request a reset link by email
- `/reset-password.html` — set a new password (opened from the emailed link)
- `/registered.html` — public count + masked names
- `/admin-login.html` — admin login
- `/admin.html` — admin dashboard (full details, approve/reject)

## Notes
- Passwords are hashed with bcrypt; they are never stored or emailed in plain text
  after the first display.
- Reset links expire after 30 minutes and can only be used once.
- Repeated wrong login attempts (5+) are temporarily blocked for 10 minutes.
