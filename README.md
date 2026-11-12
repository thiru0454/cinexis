# Cinexis

Cinexis is a single-page Tamil movie catalog with a small Node.js API for account sign-in, cross-device favorites, watch history, and anonymous viewing trends.

## Run locally

1. Install Node.js 20 or later.
2. Copy `.env.example` to `.env` and set `DATABASE_URL` to a Neon connection string. Keep `.env` private; it is ignored by Git.
3. Run `npm install` once, then `npm start`.
4. Open `http://localhost:3000`.

The server creates the required Neon tables on startup. It serves the app and API from the same origin, so account cookies are HttpOnly and the database URL stays on the server.

## Accounts and saved data

- Browsing and playback work while signed out. Signing in or creating an account is an explicit action in the Account panel; there is no automatic login dialog.
- Favorites and watch history are stored in Neon per account. Existing local browser copies are merged into the signed-in account once, then removed.
- Sessions expire after 30 days. If an expired session is detected, Cinexis asks the user to sign in again before syncing account data.
- Passwords are stored as scrypt hashes. The app does not send direct, signed movie-file URLs to the account database; history stores the catalog link and playback position so resume can resolve a fresh stream.

## Site usage

The “People using Cinexis” panel shows approximate unique browser/device visitors, visitors active in the last five minutes, and visits. A random HttpOnly cookie distinguishes browsers without requiring an account; its value is hashed before storage. Counts start when this analytics feature is deployed and do not include earlier traffic. These are browser/device estimates, not verified people, and the app does not expose identities or movie-by-movie activity.

## Deployment

The front end is static HTML, and the account/stat endpoints are Vercel Node.js Functions in `api/`.

For Vercel:

1. Keep the Vercel project root pointed at this repository folder.
2. In **Settings → Environment Variables**, add `DATABASE_URL` with the Neon connection string and `NODE_ENV` set to `production` for Production, Preview, and Development as needed. Do not add `PORT` on Vercel.
3. In **Build & Development Settings**, use the **Other** framework preset, leave the build command empty, and use `.` as the output directory if Vercel asks for one.
4. Redeploy after setting the variables. Check `/api/health` on the deployment; it should return `{"ok":true,"database":true}`.

For a regular Node.js host, set `DATABASE_URL`, `NODE_ENV=production`, and `PORT`, then run `npm start`. Use HTTPS in production; the session cookie is marked Secure when `NODE_ENV=production`. Never commit `.env` or embed the Neon connection string in browser code.
