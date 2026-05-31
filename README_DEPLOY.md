# Tezhisab Central Platform — Phase 2.1 Deployment

## What changed
- Auto cleanup keeps the latest 2 cloud installer files per software channel.
- Older files are removed automatically after a successful upload.
- Admin can manually run cleanup from App Update Manager.
- Admin can roll back to the retained previous version.

## Render deployment
Upload the updated `app.py` to the repository root. Then upload `admin/portal.html` inside the repository `admin` folder. Render will deploy automatically.

## Supabase SQL
No new SQL is required. Phase 2 SQL remains the latest schema.

## Optional Render environment variables
The defaults already match the approved setup. Add these only if you later want to change the behavior:

```text
APP_VERSION_RETENTION_COUNT=2
AUTO_DELETE_OLDER_VERSIONS=true
```
