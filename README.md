# JWT Learning and Interview Prep

## 🔑 Authentication vs Authorization

### Authentication (AuthN)
- *Who are you?*
- Verifies **identity** using credentials (username/password, OTP, biometrics, OAuth).
- Example: Logging into Facebook with correct credentials.

### Authorization (AuthZ)
- *What are you allowed to do?*
- Defines **permissions** after authentication.
- Example: An authenticated Facebook user cannot delete another user’s account unless authorized.

| Aspect | Authentication (AuthN) | Authorization (AuthZ) |
|--------|-------------------------|------------------------|
| **Definition** | Verifying identity | Determining permissions |
| **Order** | Happens first | Happens after authentication |
| **Example** | Entering correct email & password | Accessing admin dashboard |
| **Data used** | Credentials (password, OTP, biometrics) | Roles, permissions, policies |
| **Implemented by** | Login mechanism (JWT, OAuth, sessions) | Access control (RBAC, ACL, policies) |

---

## 🔹 JWT Basics

### What is JWT?
- JSON Web Token (JWT) is a **compact, URL-safe token format** used to securely transmit information between parties.
- Common use cases: **Authentication** and **Authorization**.

### Structure of JWT
```
header.payload.signature
```

1. **Header**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
2. **Payload**
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "admin",
  "exp": 1699999999
}
```
3. **Signature**
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

---

## 🔹 How JWT Works (Authentication Flow)
1. User logs in with credentials.  
2. Server validates and issues a JWT.  
3. Client stores JWT (localStorage or cookies).  
4. Client sends JWT with requests in `Authorization: Bearer <token>`.  
5. Server verifies JWT.  
6. If valid → request is processed.  

---

## 🔹 Advantages & Disadvantages

**Advantages**
- Stateless, scalable, compact, cross-platform.

**Disadvantages**
- Cannot be easily revoked once issued.
- Payload is only base64-encoded (not encrypted).

---

## 🔹 Node.js Example (JWT in Express)
```javascript
import jwt from "jsonwebtoken";

const SECRET_KEY = "mysecret";

function generateToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    SECRET_KEY,
    { expiresIn: "1h" }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}
```

---

# 🔥 Top JWT Interview Questions & Answers

### 1. What is JWT and why is it used?
- JWT (JSON Web Token) is a compact, self-contained token for secure info transfer.  
- Commonly used for authentication and authorization.

### 2. What are the parts of a JWT?
- **Header** (algorithm, type)  
- **Payload** (claims: userId, role, exp)  
- **Signature** (verifies integrity)  

### 3. How is a JWT signature generated and verified?
- Signature = `HMACSHA256(base64urlEncode(header) + "." + base64urlEncode(payload), secret)`

### 4. What is the difference between JWT and session-based authentication?
- Session-based: server stores session → stateful.  
- JWT: token is stateless, scalable.

### 5. Where should you store JWTs on the client?
- Best: HTTP-only Secure Cookies.  
- Avoid localStorage if possible (XSS risk).

### 6. What is the difference between access tokens and refresh tokens?
- **Access token**: short-lived, used to access APIs.  
- **Refresh token**: longer-lived, used to obtain new access tokens.

### 7. How do you invalidate a JWT?
- Short expiry + refresh tokens.  
- Maintain a blacklist.  
- Rotate tokens.

### 8. What algorithms are used for JWT signing?
- Symmetric: HS256, HS384, HS512.  
- Asymmetric: RS256, ES256.

### 9. What are common vulnerabilities of JWT?
- No expiry (`exp` missing).  
- Weak secret.  
- XSS if stored in localStorage.  
- Algorithm confusion.

### 10. How do you secure JWT in production?
- Use HTTPS.  
- Short expiration (`exp`).  
- Refresh tokens.  
- Store in HTTP-only cookies.  
- Strong secrets.

### 11. Can JWT be used for both Authentication and Authorization?
- Yes. Authentication proves identity, Authorization controls permissions.

### 12. What is the difference between JWT and OAuth2?
- JWT = token format.  
- OAuth2 = authorization protocol (can use JWT).

### 13. What are registered, public, and private claims in JWT?
- Registered claims: standard (iss, exp, sub).  
- Public claims: custom but avoid collisions.  
- Private claims: app-specific.

### 14. Why is JWT base64 encoded and not encrypted?
- Base64Url encoding = compact transfer, not confidentiality.  
- For encryption → use JWE.

### 15. What is the difference between JWT and JWE?
- JWT: signed, integrity only.  
- JWE: encrypted, integrity + confidentiality.

---
