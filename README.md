# 🔐 TheyCloud IAM Library

Reusable authentication and authorization system for Node.js applications. Built for modular integration into Express-based apps like **TheyCloud**.

---

## ✨ Features

- ✅ JWT-based login & registration  
- ✅ Access & refresh tokens  
- ✅ `/me` user endpoint  
- ✅ Logout with Redis invalidation  
- ✅ Token refresh  
- ✅ Role-based access control (RBAC)  
- ✅ Plug-and-play in any Express project  
- 🔐 RS256 / HS256 algorithm support  
- 🤖 Service account support with JWT  
- 📜 Audit logging for auth events  
- 🔒 Rate limiting middleware  
- 🧪 Override-friendly handler architecture  
- 👤 Profile CRUD module  

---

## 📦 Installation

```bash
pnpm install
# OR
npm install
```

If used as a submodule in your main project (e.g. TheyCloud), link it:

```bash
cd Integration/iam-lib
npm link
```

Then in your main app:

```bash
npm link iam-lib
```

---

## 🧩 Configuration

### 🔧 `createIamHandlers(config)`

```js
import { createIamHandlers, createTokenService } from 'iam-lib';
import RedisClient from '.../RedisClient.class.js';
import Logger from '.../Logger.js';
import DatabaseConnection from '.../database.connection.class.js';
import fs from 'fs';

const privateKey = fs.readFileSync('./certs/private.pem', 'utf-8');
const publicKey = fs.readFileSync('./certs/public.pem', 'utf-8');

const tokenService = createTokenService({
  algorithm: 'RS256',
  privateKey,
  publicKey,
});

const iam = createIamHandlers({
  db: DatabaseConnection.getConnection().getDbInstance(),
  redis: new RedisClient(),
  logger: Logger,
  roles: ['user', 'admin', 'support'],
  tokenService,
  getRole: async (userId) => {
    const user = await db('users').where({ id: userId }).first();
    return user?.role;
  },
});
```

---

## 🚀 Express Integration

```js
import express from 'express';

/** @param {import('iam-lib').IamHandlers} iam */
export default function AuthRoute(iam) {
  const router = express.Router();

  router.post('/register', ...iam.register);
  router.post('/login', ...iam.login);
  router.post('/refresh-token', ...iam.refreshToken);
  router.delete('/logout', iam.accessTokenMiddleware, ...iam.logout);
  router.get('/me', iam.accessTokenMiddleware, ...iam.me);

  router.get('/admin', iam.accessTokenMiddleware, iam.requireRole('admin'), (req, res) => {
    res.send('Welcome admin!');
  });

  return router;
}
```

---

## 🔐 JWT Settings

Environment variables (if using HS256):

```env
ACCESS_TOKEN_SECRET=your_access_token_secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret
ACCESS_TOKEN_LIFE=15m
REFRESH_TOKEN_LIFE=7d
```

---

## 🧠 API Summary

| Method                | Middleware                                      | Description           |
| --------------------- | ----------------------------------------------- | --------------------- |
| `POST /login`         | —                                               | Authenticate user     |
| `POST /register`      | —                                               | Create new user       |
| `POST /refresh-token` | —                                               | Get new access token  |
| `DELETE /logout`      | `accessTokenMiddleware`                         | Log out & invalidate  |
| `GET /me`             | `accessTokenMiddleware`                         | Get current user info |
| `GET /admin`          | `accessTokenMiddleware`, `requireRole('admin')` | Admin access only     |

---

## 🧪 TypeScript Support

```js
/** @typedef {import('iam-lib').IamHandlers} IamHandlers */
```

Or inline:

```js
/**
 * @param {import('iam-lib').IamHandlers} iam
 */
```

Includes `index.d.ts` for IntelliSense and validation.

---

## 🔄 Custom Handlers

All handlers can be overridden via the `overrides` config:

```js
createIamHandlers({
  overrides: {
    login: [myRateLimiter, customLoginHandler],
    me: customMeHandler
  }
});
```

---

## 🔐 Token Service

Supports both RS256 (asymmetric) and HS256 (symmetric) signing.

```js
const tokenService = createTokenService({
  algorithm: 'RS256',
  privateKey,
  publicKey,
});
```

### API
- `signAccessToken(userId, claims?)`
- `signRefreshToken(userId)`
- `verifyAccessToken(token)`
- `verifyRefreshToken(token)`
- `getArgs()` — for passing keys to middleware

---

## 🧱 Middleware

### `accessTokenMiddleware`
Injects `req.payload` from `Authorization: Bearer` header.

```js
accessTokenMiddleware({ key: publicKey, algorithm: 'RS256' })
```

### `requireRole`
Role-based access using hierarchy.

```js
If you want to use 
requireRole({ roles: ['user', 'admin'], getRole })(requiredRole)
```

or 
```js
    const userRepo = {
      getById: (id) => database.getDbInstance()("users").where({ id }).first(),
      update: (id, data) => database.getDbInstance()("users").where({ id }).update(data),
      delete: (id) => database.getDbInstance()("users").where({ id }).delete(),
    };
   const iam = createIamHandlers({
        db,
        redis,
        logger,
        roles: ['user', 'admin'],
        userRepo,
        tokenService,
        getRole: async (userId) => {
          const user = await userRepo.getById(userId);
          return user?.role;
        },
      })

      app.use("/admin",[iam.accessTokenMiddleware, iam.requireRole("admin")], (req, res) => {
        res.send ("Welcome, admin");
      })
```

---

## 🤖 Service Accounts

```js
issueServiceToken(serviceId)
verifyServiceToken(token, publicKey)
```

---

## 📜 Audit Logging

```js
auditLogger({ logger })({
  action: 'user.login',
  userId,
  ip,
  meta: { custom: 'data' }
})
```

---

## ⚙️ Rate Limiting

```js
const rateLimiter = createRateLimiter({ windowMs: 60_000, max: 10 })

app.use("/admin", [rateLimiter, iam.requireRole("admin"), iam.accessTokenMiddleware], (req, res) => {
res.send("Welcome, admin!");
})
```

---

## 📁 Folder Structure

```
iam-lib/
├── src/
│   ├── factory.js              # Entry point for createIamHandlers
│   ├── handlers/               # login, register, etc.
│   ├── middleware/             # JWT & RBAC middleware
│   ├── cloud/                  # Service account utilities
│   ├── events/                 # Audit logger
│   └── utils/                  # Token and validation utils
├── index.d.ts                  # TypeScript definitions
├── index.js                    # Export entry
└── package.json
```

---

## 🛡️ Recommended Usage

| Use Case         | Algorithm | Notes                                 |
| ---------------- | --------- | ------------------------------------- |
| Monolith Backend | HS256     | Simple shared-secret                  |
| Microservices    | RS256     | Public-key validation on each service |
| Cloud-Ready      | RS256     | Compatible with JWKS, scalable        |

---

## 💡 Future Ideas

- ⏳ Session-aware token revocation
- 🧩 OAuth2 support
- 📈 Rate limiting middleware
- 🎛 Admin control panel integration

---

## 📘 License

Creative Commons Attribution 4.0 International (CC BY 4.0)

---

## 📣 Attribution

If you use this library, please credit:

**TheyCloud IAM** by [https://github.com/hyzco]
