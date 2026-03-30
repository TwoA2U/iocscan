# Changelog

## Unreleased

### Changed

- The scan API surface is now:
  - `POST /api/scan/generic`
  - `POST /api/scan/hash/generic`
  - `POST /api/scan/ioc/generic`

### Removed

- Removed legacy typed scan endpoints:
  - `POST /api/scan`
  - `POST /api/scan/hash`
  - `POST /api/scan/ioc`
- Removed the old typed compatibility shims and transitional `legacy_api` deployment toggle.

### Notes

- The current web UI was already using the generic endpoints, so no UI migration was needed for this removal.
- New integrations should target the generic `ScanResult` flow only.
