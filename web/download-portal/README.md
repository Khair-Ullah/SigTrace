# SIEM Download Portal

Static Vercel landing page for the Windows desktop app.

## Local preview

```powershell
python -m http.server 8080 --directory web/download-portal
```

Open <http://localhost:8080>.

## Deploy

```powershell
cd web/download-portal
npx vercel --prod
```

In the Vercel dashboard, use `web/download-portal` as the **Root Directory**,
select **Other** as the framework, and leave the build command empty.

## Release the installer

1. Build the app and installer from the repository root:

   ```powershell
   .\packaging\build-desktop.ps1 -Python .\venv\Scripts\python.exe -SkipInstall -Clean -NoInstaller
   & "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" installer\SIEM.iss
   ```

2. Copy the installer:

   ```powershell
   Copy-Item installer\Output\SIEM-Setup-1.0.0.exe web\download-portal\downloads\ -Force
   ```

3. Update `downloads/version.json` with the filename, byte size and SHA-256:

   ```powershell
   $file = Get-Item web\download-portal\downloads\SIEM-Setup-1.0.0.exe
   $file.Length
   (Get-FileHash $file.FullName -Algorithm SHA256).Hash
   ```

4. Update `downloads/README.txt` if the version, install steps or hashes change.

No HTML edit is needed: `app.js` loads `version.json` and updates every
`[data-download]` link, the checksum and the visible file size.
