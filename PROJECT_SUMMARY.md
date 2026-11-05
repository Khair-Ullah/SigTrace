# SIEM Log Correlator - Final Project Summary

## Final Architecture

- **Desktop application** - Windows PyInstaller bundle that starts the backend and Flask dashboard. On first run it creates a per-user data directory under `%LOCALAPPDATA%\SIEM`, seeds configuration/rules/playbooks, creates the initial administrator, and launches the UI.
- **Processing engine** - Ingests syslog (UDP/TCP), log files, simulator data, and agent batches. Records pass through parsing, rule matching, stateful thresholds, incident correlation, persistence, notifications, and automated response.
- **Flask UI and API** - Authenticated dashboard with role-based access (`viewer`, `analyst`, `admin`), server-rendered Jinja/Tailwind pages, JSON API endpoints, audit logging, and real-time Flask-SocketIO updates.
- **SQLite storage** - WAL-mode database with migrations, indexed events/alerts/incidents, notification and audit tables, and configurable retention. Desktop data lives under `%LOCALAPPDATA%\SIEM\data`.
- **SOAR-Lite** - Playbooks in `config/playbooks.yaml` match incidents and run command or email actions. The shipped playbook is `dry_run: true`; command actions use argv lists without a shell by default, email reuses the existing SMTP configuration, duplicate responses are capped, and failures never stop detection.
- **Download portal** - Static Vercel site in `web/download-portal`; `app.js` reads `downloads/version.json` and updates download links, size, and SHA-256 metadata.

## Final Build Artifacts

| Artifact | Location | Size | SHA-256 |
| --- | --- | ---: | --- |
| Portable desktop app | `F:\SIEM\dist\SIEM\SIEM.exe` | 8,550,947 bytes | `397FE12072DBB32C314C49C0F233808035AD33CD507FC3365B4558540E73C6AD` |
| Windows installer | `F:\SIEM\installer\Output\SIEM-Setup-1.0.0.exe` | 20,447,964 bytes | `DB4236DDDB0A4BF0F92E610FC49B53114CB3D2B6CFB7C3ECA55E6DC785B8FDB8` |
| Portal download copy | `F:\SIEM\web\download-portal\downloads\SIEM-Setup-1.0.0.exe` | 20,447,964 bytes | `DB4236DDDB0A4BF0F92E610FC49B53114CB3D2B6CFB7C3ECA55E6DC785B8FDB8` |

The installer requires administrator approval during installation. The portable executable can be run without installation.

## Deploy the Portal to Vercel

The portal is a static site with no build step.

**CLI deployment:**

```powershell
cd F:\SIEM\web\download-portal
npx vercel --prod
```

**Dashboard deployment:**

1. Import the repository into Vercel.
2. Set **Root Directory** to `web/download-portal`.
3. Select **Other** as the framework preset.
4. Leave the build command and output directory empty.
5. Deploy.

**Publishing a future release:**

1. Build the new app and installer.
2. Copy the installer into `web/download-portal/downloads/`.
3. Update `web/download-portal/downloads/version.json` with the filename, byte size, and SHA-256.
4. Update `web/download-portal/downloads/README.txt` if install notes or hashes changed.
5. Deploy again. No HTML changes are needed.

## Verification

- Full automated suite: **432 tests passed**.
- Frozen desktop selftest: **passed** with `ok=true`, `frozen=true`, 9 rules loaded, admin created, and SOAR playbooks available.
- Portal JavaScript syntax check passed; installer size and SHA-256 match `version.json` and `README.txt`.
- Final manual validation: run the installer interactively and complete the elevated UAC installation flow.

Deployment and project presentation are ready.
