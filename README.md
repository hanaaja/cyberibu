# CyberIbu V10 — Netlify Ready

CyberIbu adalah web edukasi keamanan digital keluarga dengan pemeriksa URL berbasis analisis lokal dan reputasi VirusTotal.

## Deploy gratis ke Netlify

1. Upload/push seluruh isi folder ini ke repository GitHub `cyberibu`.
2. Jangan upload file `.env` yang berisi API key asli.
3. Login ke Netlify dan pilih **Add new project / Import an existing project**.
4. Hubungkan GitHub dan pilih repository `hanaaja/cyberibu`.
5. Netlify akan membaca `netlify.toml` otomatis. Publish directory adalah root project dan functions directory adalah `netlify/functions`.
6. Di Netlify buka **Site configuration → Environment variables**.
7. Tambahkan:

   `VIRUSTOTAL_API_KEY` = API key VirusTotal kamu

8. Deploy site.

Frontend tetap memanggil `/api/check-url`. `netlify.toml` akan meneruskannya secara internal ke Netlify Function `/.netlify/functions/check-url`.

## Local development

Versi `server.js` tetap disertakan untuk pengujian lokal dengan Node.js. Untuk local server tradisional:

```powershell
$env:PORT=8001
node server.js
```

Lalu buka `http://localhost:8001`.

## Keamanan

- `.env` sudah di-ignore oleh Git.
- Jangan menaruh `VIRUSTOTAL_API_KEY` di `index.html` atau file JavaScript frontend.
- CyberIbu hanya membaca laporan VirusTotal yang sudah tersedia dan tidak otomatis submit URL baru.
- Hasil adalah indikator risiko, bukan jaminan absolut sebuah URL aman.
