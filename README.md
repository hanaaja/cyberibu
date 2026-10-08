# CyberIbu V9 — Multi Risk Classification

Perubahan utama:
- Hasil sekarang selalu menampilkan 4 kategori terpisah:
  - Phishing
  - Scam / Penipuan
  - Malware
  - VirusTotal
- Malware tidak akan dipaksakan muncul hanya karena URL terlihat seperti phishing.
- Malware dianggap terindikasi jika:
  - URL mengarah ke file executable seperti APK/EXE/script, atau
  - VirusTotal memberi deteksi malicious/malware.
- Phishing/scam tetap dapat muncul walau malware belum terdeteksi.

Contoh:
`https://akun-diblokir.example/verify-otp`
bisa menghasilkan:
- Phishing: TERINDIKASI
- Scam/Penipuan: TERINDIKASI
- Malware: Belum terdeteksi
- VirusTotal: Belum ada laporan

Ini lebih akurat daripada menyatukan semua risiko ke satu label.
