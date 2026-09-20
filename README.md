# SecureAuth – Secure Login System with Password Hashing

## Objective
SecureAuth is a college cybersecurity mini project that demonstrates secure user registration, authentication, bcrypt password hashing, and basic brute-force protection in a clear 5-minute demo.

## Problem statement
Storing plaintext passwords puts users at risk. This project shows how applications should store a one-way bcrypt password hash instead, then verify a login attempt against that hash.

## Features
- Registration with server-side and client-side validation
- bcrypt password hashing; plaintext passwords are never saved or displayed
- Secure login with generic failure messages
- Flask session-based protected Dashboard and Security Center
- Five failed consecutive attempts lock an account for five minutes
- SQLite user records and authentication audit logs
- CSRF token on every POST form
- Responsive, cybersecurity-themed interface

## Technologies
Python, Flask, SQLite, bcrypt, HTML5, CSS3 and vanilla JavaScript.

## System architecture
Browser → Flask routes → validation/authentication logic → SQLite database. Passwords pass through bcrypt before database storage. Login uses bcrypt verification against the stored hash.

## Database structure
`users`: `id`, `username`, `email`, `password_hash`, `failed_attempts`, `locked_until`, `last_login`, `created_at`.

`login_logs`: `id`, `user_id`, `event_type`, `timestamp`. Events include `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, and `LOGOUT`.

## How bcrypt works
bcrypt generates a salted, one-way hash. The stored value includes the salt and cost setting. At login, `bcrypt.checkpw()` hashes/verifies the entered password against the stored bcrypt value. It does not decrypt anything.

## Why hashing instead of encryption?
Passwords should be hashed because the server has no legitimate need to recover the original password. Encryption is reversible if a key is compromised; a password hash is designed to be one-way.

## Authentication flow
Register: validate → bcrypt hash → store hash in SQLite.

Login: find user by email → check lockout → bcrypt verify → create Flask session or record a failed attempt.

## Security features
Parameterized SQLite queries, input validation, bcrypt, generic login errors, session protection, CSRF tokens, protected routes, logout clearing, and temporary brute-force lockout.

## Run locally or on Replit
1. Create a Python Replit project and upload these files/folders.
2. In the Shell, run `pip install -r requirements.txt`.
3. Run `python app.py`.
4. Open the web preview. The SQLite database is created automatically as `secureauth.db`.

For deployment, set a unique `SECRET_KEY` environment variable and turn off Flask debug mode.

## Demo steps
1. Open Home and explain the bcrypt flow.
2. Register with a strong password and point out the password-strength meter.
3. Log in successfully and view the Dashboard.
4. Visit Security Center to show a truncated bcrypt hash (never the password).
5. Log out; try an incorrect password to demonstrate generic errors.
6. Try five incorrect passwords to demonstrate the five-minute temporary account lock.

## Limitations and future improvements
This is an educational mini project, not production-grade security. Future work could add email verification, password reset flows, HTTPS deployment, rate limiting by IP, database migrations, secure production session configuration, and automated tests.
