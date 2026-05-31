# Tezhisab Central Platform — Phase 2.1

## Storage Control Upgrade
- Automatically keeps only the latest 2 centrally uploaded installer files per software channel.
- Automatically removes older R2 objects and their app-version metadata after each successful upload.
- Adds a one-click **Clean Older Files Now** action in App Update Manager.
- Adds a **Rollback** action for the retained previous version.
- Displays the current **Latest** version clearly in the published versions list.
- Fixes the missing pathlib import used during file validation.

No new Supabase SQL is required for this release.
