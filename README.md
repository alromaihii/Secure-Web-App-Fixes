# WireGuard Flask App – Security Analysis & Fixes

This repository contains a Flask-based WireGuard configuration management app provided by the professor for vulnerability assessment. The original app (`wgflask.orig`) contained multiple security issues, which have been identified, exploited, and fixed in this modified version (`wgflask`).

---

## Table of Contents
1. [Overview](#overview)  
2. [Threat Model Analysis (STRIDE)](#threat-model-analysis-stride)  
3. [Identified Vulnerabilities & Exploits](#identified-vulnerabilities--exploits)  
4. [Defense-in-Depth Fixes](#defense-in-depth-fixes)  
5. [Proposed Redesign](#proposed-redesign)  
6. [Project Structure](#project-structure)  
7. [Diff & Fixes](#diff--fixes)  

---

## Overview
The app manages WireGuard server and client configurations. The goal of this project is to analyze the security of the original code, identify vulnerabilities, and apply fixes following **defense-in-depth principles**.

---

## Threat Model Analysis (STRIDE)

1. **Spoofing**  
   - Login in `auth.py` uses only email/password without MFA.  
   - `session['role']` can be manipulated, allowing privilege escalation.  

2. **Tampering**  
   - Config files in `main.py` and `wgconfig.py` are in plaintext and modifiable.  
   - The download endpoint allows arbitrary file access.  

3. **Repudiation**  
   - No logging of user activity. Users can deny actions, and the system cannot prove changes occurred.  

4. **Information Disclosure**  
   - Sensitive configs (`admin_server.conf`) are stored in plaintext.  
   - Generated keys in `wgkeys.py` are not stored securely.  

5. **Denial of Service**  
   - Sensitive endpoints have no rate limiting.  
   - Resource-heavy operations (file creation, key generation) can exhaust server resources.  

6. **Elevation of Privilege**  
   - `session['role']` determines permissions, which can be modified.  
   - Users can guess filenames to access admin files.

---

## Identified Vulnerabilities & Exploits

1. **Filename-based authentication**  
   - Users with the same username can access each other's configs.  
   - **Exploit:** Download another user's file by guessing the username.  

2. **Unauthorized admin access**  
   - Users can request `admin_client.conf`.  
   - **Exploit:** Guess the filename to download sensitive admin configs.  

3. **Lack of encryption**  
   - Configs stored in plaintext.  
   - **Exploit:** Anyone with filesystem access can read sensitive files.

---

## Defense-in-Depth Fixes

- **Encrypted storage**  
  - Files now encrypted with `cryptography.Fernet` using user-specific keys derived from `user_id`.  
  - Admin files use separate admin-derived keys.  

- **Access control**  
  - Download logic differentiates between admin and user roles.  
  - Users can only decrypt and access their own files.  

- **Secure handling of configurations**  
  - Added `save_configuration` and `load_configuration` functions for encryption and decryption.  
  - Admin configs encrypted and only decrypted for authenticated admins.  

---

## Proposed Redesign

1. **Authentication & Authorization**  
   - Add MFA using OAuth2/OpenID Connect.  
   - Centralized RBAC.  
   - Signed and encrypted session cookies with Redis.  

2. **Data Storage & Management**  
   - AES-256 encryption for configs.  
   - User-specific encryption keys with PBKDF2HMAC.  
   - Audit logs for read/write actions.  

3. **Network Security**  
   - Validate user access to files before download.  
   - Rate limiting using Flask-Limiter.  
   - Prevent arbitrary file access using whitelisted directories and dynamic file mapping.

---

## Project Structure

wgflask/
├── code-docker-compose.yml
├── Dockerfile
├── flaskAPP-configs-admin_client.conf
├── admin_server.conf
├── instance-db.sqlite
├── wgflask_init.py
├── auth.py
├── forms.py
├── main.py
├── models.py
├── peer.py
├── requirements.txt
├── wgconfig.py
├── wgkeys.py
├── static/
└── templates/
├── base.html
├── index.html
├── login.html
├── profile.html
├── signup.html
└── wgconfig.html


---
## Diff & Fixes

Full diff file is available as question3.diff for reference.

