# Tezhisab Central Platform — Phase 2.2 Updater Channel Fix

## Fixed
- Secure installed-app update checks now correctly normalize `WINDOWS_EXE` to the existing database channel code `WINDOWSEXE`.
- Removed the update-channel truncation mismatch that caused Bank Import Pro V1.0.33 to silently fall back to its local manifest and incorrectly report that V1.0.33 was the latest version even after V1.0.34 had been published.
- Added backward compatibility for any earlier channel rows saved with truncated codes such as `WINDOWSE`.

## Database
- No Supabase SQL migration is required.

## Environment
- No Render environment-variable change is required.
