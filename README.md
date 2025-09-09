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

## 🔹 Why should we use JWT as compared to other methods?
- Let's talk about the benefits of JSON Web Tokens (JWT) when compared to **Simple Web Tokens (SWT)** and **Security Assertion Markup Language Tokens (SAML)**.
- As JSON is less verbose than XML, when it is encoded, its size is also smaller, making JWT more compact than SAML. This makes JWT a good choice to be passed in HTML and HTTP environments.
- Security-wise, SWT can only be symmetrically signed by a shared secret using the HMAC algorithm. However, JWT and SAML tokens can use a public/private key pair in the form of an X.509 certificate for signing. Signing XML with an XML Digital Signature without introducing obscure security holes is very difficult compared to the simplicity of signing a JSON.
- JSON parsers are common in most programming languages because they map directly to objects. Conversely, XML doesn't have a natural document-to-object mapping. This makes it easier to work with JWT than SAML assertions.
- Regarding usage, JWT is used at the Internet scale. This highlights the ease of client-side processing of the JSON Web token on multiple platforms, especially mobile.

## 🔹 What is the difference between validating and verifying a JWT?
- Validation ensures the token is well-formed and contains enforceable claims. JWT validation generally refers to checking the structure, format, and content of the JWT:
Structure: Ensuring the token has the standard three parts (header, payload, signature) separated by dots.
Format: Verifying that each part is correctly encoded (Base64URL) and that the payload contains expected claims.
Content: Checking if the claims within the payload are correct, such as expiration time (exp), issued at (iat), not before (nbf), among others, to ensure the token isn't expired, isn't used before its time, etc.

- Verification ensures the token is genuine and unmodified. JWT verification involves confirming the authenticity and integrity of the token:
Signature Verification: This is the primary aspect of verification where the signature part of the JWT is checked against the header and payload. This is done using the algorithm specified in the header (like HMAC, RSA, or ECDSA) with a secret key or public key. If the signature doesn't match what's expected, the token might have been tampered with or is not from a trusted source.
Issuer Verification: Checking if the iss claim matches an expected issuer.
Audience Check: Ensuring the aud claim matches the expected audience.
In practical terms:

## 🔹 Explain Decoding and Encoding of JWT?

- Encoding a JWT involves transforming the header and payload into a compact, URL-safe format. The header, which states the signing algorithm and token type, and the payload, which includes claims like subject, expiration, and issue time, are both converted to JSON then Base64URL encoded. These encoded parts are then concatenated with a dot, after which a signature is generated using the algorithm specified in the header with a secret or private key. This signature is also Base64URL encoded, resulting in the final JWT string that represents the token in a format suitable for transmission or storage.

- Decoding a JWT reverses this process by converting the Base64URL encoded header and payload back into JSON, allowing anyone to read these parts without needing a key. However, "decoding" in this context often extends to include verification of the token's signature. This verification step involves re-signing the decoded header and payload with the same algorithm and key used initially, then comparing this new signature with the one included in the JWT. If they match, it confirms the token's integrity and authenticity, ensuring it hasn't been tampered with since issuance.

# Refresh Tokens Explained

**Why do we need refresh tokens?**
- **Access tokens (JWTs)** are short-lived (e.g., 5–15 minutes).  
  - ✅ Good: limits damage if stolen.  
  - ❌ Bad: user would need to log in very often.  

- **Refresh tokens** solve this by letting the client get a *new* access token without re-authentication.

---

**How refresh tokens work**
1. User logs in → server issues:
   - **Access token** (short-lived JWT, used for APIs).  
   - **Refresh token** (long-lived, secret, used to get new access tokens).  

2. Client stores them:
   - Access token → sent with each API request.  
   - Refresh token → kept securely (cookie or secure storage).  

3. When access token expires:
   - Client sends refresh token to server.  
   - Server verifies → issues a new access token (and often a new refresh token).  

---

**Characteristics**
- Longer lifetime than access tokens.  
- Must be stored securely (if stolen, attacker can mint tokens).  
- Often tracked server-side for revocation.  
- Can be **rotating** (new one issued each time to prevent replay).


## 🔹 Explain all types of claims in payload of JWT?
- **Registered claims** — what they are and the common ones
These are defined in RFC 7519; they provide interoperable, well-understood semantics:

iss (Issuer) — string: who issued the token (URI or identifier).

sub (Subject) — string: principal (usually user id) the token refers to.

aud (Audience) — string or array of strings: intended recipients (one or more). Must be checked by the receiver.

exp (Expiration Time) — NumericDate: time after which the token MUST NOT be accepted. (seconds since Unix epoch).

nbf (Not Before) — NumericDate: token must not be accepted before this time.

iat (Issued At) — NumericDate: time when the token was issued.

jti (JWT ID) — string: unique id for the token (useful for revocation/blacklist).

Notes:

NumericDate is in seconds since epoch (so in JavaScript divide Date.now() by 1000).

aud may be a single string or an array of strings.

Registered claims are recommended for interoperability — e.g., always check exp and (if present) nbf.

- **Public claims** — what they mean and how to avoid collisions

Public claims are names you choose that are intended to be commonly known and used across systems (for example: name, email, scope, role).

Collision avoidance:

Register the claim name in the IANA JSON Web Token Claims registry (so others know the meaning), or

Use a URI as the claim name to create a collision-resistant namespace, e.g.
"https://acme.example.com/claims/role": "admin".
(That URI need not be dereferenceable; it’s just a namespace.)

“Public” here does not mean the value is publicly visible — a JWT payload is base64url-encoded but not encrypted. If the data is sensitive, encrypt (JWE) or avoid putting it in the token.

- **Private claims** — when and how to use

Private claims are custom fields agreed on by specific parties (client + server). Example: company_id, account_tier.

Because they’re not registered, name collisions can happen if two parties independently choose the same key for different meanings. Use namespacing (URI or company prefix) to reduce risk.

Private claims are fine for internal metadata, but:

avoid putting secret PII in plain JWTs unless the token is encrypted (JWE).

prefer storing large or frequently-changing data on the server and keep the JWT small (only an identifier).
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
- How session-based authentication works
  Flow:
    - User logs in with credentials.
    - Server creates a session (an object in server memory or a database) containing user info.
    - Server sets a session ID in a cookie (Set-Cookie).
    - On each request, browser sends the cookie.
    - Server looks up the session ID in its store → retrieves user data → authorizes.
  Characteristics:
    - State is stored on the server (session store: memory, Redis, DB).
    - Token is usually just a random session ID (no data inside).
    - Revoking a session is easy → just delete it from the store.
    - Works well when you have a single server or shared session store.

- How JWT-based authentication works
  Flow:
    - User logs in with credentials.
    - Server issues a JWT (signed JSON payload: user id, roles, exp, etc.).
    - JWT is sent to the client (often stored in Authorization: Bearer <token> header).
    - On each request, client sends the JWT.
    - Server verifies the signature and reads claims directly → no lookup needed.
  Characteristics:
    - State is stored in the token itself (stateless).
    - Server doesn’t need to store per-user session data.
    - Token revocation is harder (since the server doesn’t track them).
    - Great for distributed / microservice architectures, where you don’t want to share a session store.

- Use session-based auth when:
  - You control a single backend (monolith or small-scale).
  - You need easy logout/revocation.
  - You mostly serve web clients (cookies integrate well).

- Use JWT when:
  - You have multiple backends / microservices (stateless verification is a win).
  - You need to authenticate APIs, mobile apps, or 3rd-party clients.
  - You accept that revocation will be handled via short lifetimes + refresh tokens.

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
