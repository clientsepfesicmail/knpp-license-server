# Tezhisab Central Platform — License Server Phase 1

This is the upgraded backend for the existing live license server:

`https://knpp-license-server.onrender.com/`

## What is included

- New central portal at `/portal` and `/`
- Email + password login
- Two approved admin email accounts:
  - `capinkupatowary@gmail.com`
  - `prodip252@gmail.com`
- Customer login with email + password
- Customer Master
- Software Product Master
- Admin-side **Create New Software**
- License generation, renewal, suspension and reactivation
- Software update channels
- Manual GitHub repository mapping
- Manual app-version publishing using GitHub release download URLs
- Customer dashboard with licensed software, expiry date and download links
- Existing `/activate` and `/verify` desktop-app licensing APIs preserved
- Legacy password dashboard available at `/legacy-admin`

## Important: Phase 1 vs Phase 2

Phase 1 is intentionally safe. It lets you store repository mappings and publish version/download URLs from the central portal.

Direct EXE/APK upload to GitHub Releases is **not enabled yet**. That will be added in Phase 2 after secure GitHub authorization. Never put GitHub passwords, personal access tokens or secrets inside Flutter or browser code.

## Supabase SQL — run first

Open the existing Supabase project used by the license server.

Go to:

`Supabase Dashboard → SQL Editor → New Query`

Paste and run:

`TEZHISAB_CENTRAL_PORTAL_SETUP.sql`

This script preserves existing licenses and adds the new portal tables.

## Render deployment

Replace the current Render server files with the files from this folder and redeploy.

Required Render environment variables:

```text
SUPABASE_URL=<existing value>
SUPABASE_KEY=<existing value>
ADMIN_PASSWORD=<existing admin password>
SERVER_SECRET=<strong secret value>
ADMIN_EMAILS=capinkupatowary@gmail.com,prodip252@gmail.com
SESSION_HOURS=24
```

`ADMIN_PASSWORD` is used only for first-login bootstrap of the two approved admin emails and for the temporary legacy dashboard.

## First admin login

After SQL and Render deployment:

1. Open `https://knpp-license-server.onrender.com/portal`
2. Login using either approved admin email.
3. For the first login, use the existing Render `ADMIN_PASSWORD`.
4. Open **Settings** and change the password.
5. Repeat for the second admin email.

Each admin account will then have its own hashed password in the database.

## Customer account workflow

1. Admin Portal → Customers → Add Customer
2. Enter customer email and initial password
3. Admin Portal → Licenses → Generate License
4. Select the customer and software product
5. Customer logs in using email + password
6. Customer sees only licenses linked to their email

## Existing repository mappings included

Detected from the uploaded working applications:

```text
Bank Import Pro
Repository: tezhisab-afk / bank-import-pro-updates
Manifest: https://raw.githubusercontent.com/tezhisab-afk/bank-import-pro-updates/main/version.json

EPF & ESIC Manager
Repository: clientsepfesicmail / -epf-esic-updates
Manifest: https://clientsepfesicmail.github.io/-epf-esic-updates/version.json
```

## Product codes preserved

```text
TallySync Pro: TSP
EPF & ESIC Manager: EEM
Bank Import Pro: BIP
TezHisab Prime / Invoice Management: THP
EDU PRIME: EDUPRIME
```

## EDU PRIME update channels prepared

```text
EDU PRIME Desktop App — EXE
EDU PRIME Teacher App — APK
EDU PRIME Parent App — APK
```


## Phase 1.1 patch — Trial keys, license delete and visible dropdowns

This patch adds:
- clear dark text on light browser drop-down options for customer and software selection;
- Delete button for demo/test/unwanted license records;
- standard license or trial key creation with presets for 7, 10, 15 and 30 days, plus custom validity days.

No new Supabase SQL is required for this patch. Existing license records remain compatible.
