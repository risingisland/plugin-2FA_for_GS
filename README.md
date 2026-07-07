# Welcome to the `2FA for GS` wiki!

# 🔐 2FA for GS

Add **Two-Factor Authentication (2FA)** to your GetSimple CMS admin login using any TOTP-compatible app such as Google Authenticator, Authy, or 1Password.

<img width="1200" alt="screenshot" src="https://github.com/user-attachments/assets/69b3744e-17c7-47d9-9304-9a26cc176b99" />


---

## ✨ Features

- 🔒 Secure admin login with TOTP (RFC 6238)
- 📱 Works with Google Authenticator, Authy, 1Password, and more
- 🔑 Single-use recovery codes
- 🧠 SQLite-based storage (no external dependencies)
- ⚡ Lightweight and self-contained
- 🍪 Session-based verification (configurable duration)
- 🎯 Seamless integration with GetSimple CMS

---

## 📦 Requirements

- GetSimple CMS
- PHP with:
  - SQLite3 enabled
  - Standard extensions (`hash`, `openssl`)

---

## 🚀 Installation

1. Upload the plugin file:

   ```bash
   2FAforGS.php
   ```

   to:

   ```bash
   /plugins/
   ```

2. Log into your admin panel

3. Activate the plugin:

   ```
   Plugins → 2FA for GS
   ```

---

## ⚙️ Setup Guide

1. Go to:

   ```
   Settings → 2FA for GS
   ```

2. Click **Enroll Now**

3. Scan the QR code with your authenticator app  
   OR enter the secret manually

4. Enter the 6-digit code to confirm

---

## 📱 Supported Apps

- Google Authenticator  
- Authy  
- 1Password  
- Any TOTP-compatible app  

---

## 🔑 Login Flow

1. Enter your username and password  
2. If 2FA is enabled, you’ll be prompted for a code  
3. Enter either:
   - Authenticator code  
   - OR Recovery code  

---

## 🧯 Recovery Codes

- 8 recovery codes are generated during setup  
- Each code can only be used once  

⚠️ **Recovery codes are only shown once — store them securely.**

### 🔄 Regenerating Codes

```
Settings → 2FA for GS → Regenerate Codes
```

- Old codes will stop working after regeneration  

---

## 🔄 Resetting 2FA

```
Settings → 2FA for GS → Reset 2FA
```

This will:
- Remove your secret  
- Disable 2FA  
- Require re-enrollment  

---

## ⚙️ Configuration

### 🍪 Cookie Duration

Default (3 hours):

```php
setcookie(GS2FA_COOKIE, '1', time() + 10800, '/', '', false, true);
```

### ⏱ Common Values

| Duration        | Value |
|----------------|------|
| Session only    | 0    |
| 1 hour          | 3600 |
| 3 hours         | 10800 |

---

## 🗄️ Database

Location:

```
/data/other/gs_2fa.db
```

---

## 🛡️ Security Notes

- Secrets stored in SQLite database  
- Recovery codes hashed using `password_hash()`  
- TOTP uses RFC 6238  
- Time drift tolerance: ±1 window  
- Uses HTTP-only cookies  

---

## 🐞 Troubleshooting

### SQLite Error

Make sure SQLite3 is enabled:

```ini
extension=sqlite3
```

---

### Locked Out

- Use a recovery code  
- Or delete:

```
/data/other/gs_2fa.db
```

---

## ❤️ Support / Donate

https://getsimple-ce.ovh/donate  

---

