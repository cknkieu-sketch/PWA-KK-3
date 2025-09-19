# PassVault — Fresh Build

A simple mobile-friendly, **offline** password vault. Data is encrypted on-device with AES‑GCM. Unlock with **biometrics (WebAuthn on Chrome, HTTPS)** and **PIN** fallback. Includes password generator and **encrypted import/export** (.vault).

## Features
- Installable PWA (Chrome → Add to Home screen), offline via Service Worker
- AES‑GCM 256-bit vault encryption; master key wrapped by PIN (PBKDF2-SHA256 150k)
- Optional **biometric gating** (WebAuthn) with `rp.id = location.hostname`
- Password generator: length 8–64, lowercase/UPPERCASE/numbers/symbols
- Encrypted backup import/export with a **backup password** (PBKDF2 200k)

## Use
1. Open `index.html` (for full features, host on **HTTPS** or `http://localhost`).
2. Create **PIN**, optionally enable **biometrics**.
3. Add entries; **Export Encrypted Backup** to `.vault` file.
4. Restore on a new device with **Import Backup** (biometrics off after restore; re-enable from setup).

## Deploy on GitHub Pages
- Push these files to a repo → Settings → Pages → deploy **root**.
- Open the site in Chrome on your phone → **Add to Home screen**.

© 2025-09-19


## Save backups to SD card (Android / Chrome)
- Tap **Choose Backup Folder** → select your SD card directory in the system picker.
- Tap **Save Backup to Folder** to write `.vault` directly there.
- If your Chrome doesn’t support folder picking yet, the app will fall back to the standard download prompt; you can then choose the SD card in the system dialog.
