# Installed App Update API Integration

Future desktop/mobile app builds should call:

`POST https://knpp-license-server.onrender.com/api/v2/updates/check`

JSON body example:

```json
{
  "license_key": "CUSTOMER-LICENSE-KEY",
  "product": "BIP",
  "channel": "WINDOWS_EXE",
  "current_version": "1.0.31",
  "machine_id": "activated-machine-id"
}
```

The response returns `update_available`, license validity, update notes, update type and a short-lived secure download URL when a newer centrally uploaded version exists.

The current `/updates/check` endpoint remains available for older apps during migration.
