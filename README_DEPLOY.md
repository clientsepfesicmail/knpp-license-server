# Tezhisab Central Platform Phase 2 Deployment

## What changed
The Admin Portal can now upload EXE/APK/MSI/ZIP app files directly to Cloudflare R2 central storage. Customers download authorized software through their portal login. Existing external/GitHub links remain supported during migration.

## 1. Run latest Supabase SQL
Run only `TEZHISAB_CENTRAL_STORAGE_PHASE2.sql` in Supabase SQL Editor.

## 2. Configure Cloudflare R2
Create one R2 bucket named `tezhisab-app-updates`. Create an R2 API token limited to that bucket with Object Read & Write permission. Keep the Access Key ID and Secret Access Key private.

## 3. Configure R2 CORS
Apply `R2_CORS_POLICY.json` to the private R2 bucket so the Admin Portal can upload files directly using secure presigned URLs.

## 4. Add Render Environment Variables
Use the variable names listed in `RENDER_ENVIRONMENT_VARIABLES_PHASE2.txt`.

## 5. Deploy backend files
Upload the updated files to the connected GitHub repository. Render will auto-deploy.

## 6. Verify
Login to `/portal`, open App Update Manager, and confirm the Central Cloud Storage card shows Ready.
