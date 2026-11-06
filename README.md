# Cassey Manwa Coffee – Shop Management System
Node.js + Express + MySQL, with dynamic **PayMongo QR Ph** payments.

Pages: `/` customer site (menu, cart, checkout, tracking) · `/staff.html` staff portal (POS, Kitchen, Orders, Products, Inventory, Users, Reports).

## 1. Run locally
1. Install Node 18+ and MySQL.
2. Create a database, then import `database/schema.sql`.
3. `cp .env.example .env` and fill it in. Generate JWT_SECRET: `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
4. `npm install`
5. `npm run create-admin -- "Cassey Manwa" you@email.com YourStrongPassword`
6. `npm start`, then open http://localhost:3000 and http://localhost:3000/staff.html
7. Create cashier and kitchen logins in Staff > Users.

## 2. PayMongo setup (needed before QR payments work)
1. In the PayMongo dashboard, get QR Ph activated for your account.
2. Developers > API Keys: copy the secret and public keys into `.env`.
3. Developers > Webhooks: add `https://YOUR-DOMAIN/api/webhooks/paymongo` with events `payment.paid` and `qrph.expired`. Copy the signing secret (`whsk_...`) to `PAYMONGO_WEBHOOK_SECRET`.
4. WARNING: PayMongo states that QR Ph codes made with TEST keys are real, live QR codes. Do not scan and pay them while testing unless you want a real transfer.

How payments are verified: each order gets its own single-use QR for the exact total. The order is marked paid only when PayMongo's signed `payment.paid` webhook arrives (HMAC verified, amount checked against the order total) or when PayMongo's API reports the payment intent as `succeeded`. Nothing is simulated. A unique payment id, row locking and a paid-check make duplicate webhooks harmless. Stock is deducted once, at payment time. Cash sales (POS) are marked paid by a cashier.

## 3. Deploy on GoDaddy
Node.js apps need either **cPanel hosting that includes "Setup Node.js App"** or a **GoDaddy VPS**. Basic shared plans may not include Node.js, so check your plan or ask GoDaddy support first. HTTPS is required for PayMongo webhooks.

### Option A: cPanel with Node.js
1. cPanel > MySQL Databases: create a database and user, add the user to the database with all privileges.
2. phpMyAdmin: select the database and import `database/schema.sql`.
3. Upload the project zip with File Manager to e.g. `/home/USER/coffee` and extract it (do not upload `node_modules`).
4. cPanel > Setup Node.js App > Create Application: Node 18+, mode Production, application root `coffee`, startup file `server.js`.
5. Add environment variables from `.env.example` (DB_HOST=localhost and the cPanel-prefixed DB name and user).
6. Click Run NPM Install, then Restart.
7. Open the Terminal (or the virtual environment command shown on the Node.js App page) and run `npm run create-admin -- "Name" email password`.
8. Install the free SSL (AutoSSL) for your domain, then add the webhook URL in PayMongo.

### Option B: GoDaddy VPS
Install Node 18+, MySQL and nginx, then run `npm ci --omit=dev` and keep the app alive with `pm2 start server.js --name coffee`. Proxy nginx to port 3000 and add SSL with Let's Encrypt (certbot).

## 4. Security notes
Passwords are hashed with bcrypt. Logins are rate-limited. APIs are protected by role-based JWT. Prices and totals are always computed on the server. Keys live only in `.env`. Never commit `.env`.

## 5. Deploy on Vercel (serverless)
Vercel runs the Express app as a serverless function (`api/index.js`) and serves `public/` as static files. Vercel does NOT host MySQL, so you need a hosted MySQL that accepts internet connections with TLS (for example TiDB Cloud Serverless, Aiven or Railway). GoDaddy's MySQL is usually not reachable from Vercel.

1. Create the hosted MySQL database and run `database/schema.sql` in its SQL console.
2. Push this folder to a GitHub repo. On vercel.com choose Add New > Project, import it, leave Framework Preset as "Other" and deploy (vercel.json already sets the output folder and API rewrite). Or from this folder run `npx vercel --prod`.
3. Project > Settings > Environment Variables: add every name in `.env.example` (DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME, DB_SSL, JWT_SECRET, PAYMONGO_SECRET_KEY, PAYMONGO_PUBLIC_KEY, PAYMONGO_WEBHOOK_SECRET). Mark secrets as Sensitive. Redeploy afterwards, because env changes only apply to new deployments.
4. Create the first admin from your own computer (put the same DB values in a local `.env`): `npm install` then `npm run create-admin -- "Cassey Manwa" you@email.com YourStrongPassword`.
5. In PayMongo > Developers > Webhooks add `https://YOUR-PROJECT.vercel.app/api/webhooks/paymongo` (events `payment.paid`, `qrph.expired`). If PayMongo gets a Vercel login page instead of a response, turn off Deployment Protection for production (Project > Settings > Deployment Protection).
6. Until all variables are set, `/api/*` answers "Server not configured. Missing: ..." which tells you what is absent.

Notes: the webhook re-confirms every payment with PayMongo's API before marking an order paid, so it stays safe even if the platform alters the request body. Vercel's free Hobby plan is meant for non-commercial use, so a real shop should use a Pro plan. A single serverless function handles the whole API, so keep MySQL connection limits in mind (the pool is capped at 3 per instance).
