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
import { createIamHandlers } from 'iam-lib';
import RedisClient from '.../RedisClient.class.js';
import Logger from '.../Logger.js';
import DatabaseConnection from '.../database.connection.class.js';

const iam = createIamHandlers({
  db: DatabaseConnection.getConnection().getDbInstance(),
  redis: new RedisClient(),
  logger: Logger,
  roles: ['user', 'admin', 'support']
});
```

---

## 🚀 Express Integration

```js
import express from 'express';

/** @param {import('iam-lib').IamHandlers} iam */
export default function AuthRoute(iam) {
  const router = express.Router();

  router.post('/register', iam.register);
  router.post('/login', iam.login);
  router.post('/refresh-token', iam.refreshToken);
  router.delete('/logout', iam.verifyAccessToken, iam.logout);
  router.get('/me', iam.verifyAccessToken, iam.me);

  // Protected route
  router.get('/admin', iam.verifyAccessToken, iam.requireRole('admin'), (req, res) => {
    res.send('Welcome admin!');
  });

  return router;
}
```

---

## 🔐 JWT Settings

Environment variables:

```env
ACCESS_TOKEN_SECRET=your_access_token_secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret
ACCESS_TOKEN_LIFE=15m
REFRESH_TOKEN_LIFE=7d
```

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

## 🧠 API Summary

| Method              | Middleware               | Description              |
|---------------------|--------------------------|--------------------------|
| `POST /login`       | —                        | Authenticate user        |
| `POST /register`    | —                        | Create new user          |
| `POST /refresh-token` | —                      | Get new access token     |
| `DELETE /logout`    | `verifyAccessToken`      | Log out & invalidate     |
| `GET /me`           | `verifyAccessToken`      | Get current user info    |
| `GET /admin`        | `verifyAccessToken`, `requireRole('admin')` | Admin access only |

---

## 📁 Folder Structure

```
iam-lib/
├── src/
│   ├── factory.js              # Entry point for createIamHandlers
│   ├── index.js                # Exports all handlers
│   ├── handlers/               # login, register, etc.
│   ├── middleware/             # JWT & RBAC middleware
│   ├── utils/                  # JWT token functions
│   └── types.js                # Optional type definitions
├── index.d.ts                  # Exports IamHandlers type
└── package.json
```

---

## 💡 Future Ideas

- ⏳ Session-aware token revocation
- 🧩 OAuth2 support
- 📈 Rate limiting middleware
- 🎛 Admin control panel integration

---

## 📜 License

Creative Commons Attribution 4.0 International (CC BY 4.0)

## 📣 Attribution

If you use this library, please credit:

**TheyCloud IAM** by [https://github.com/hyzco]