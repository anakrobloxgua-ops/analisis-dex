# DEXTRACE — APK Analyzer (Vercel)

## Fitur
- Upload APK hingga 20 MB.
- Memindai `classes.dex`, `classes2.dex`, dan seterusnya (maks. 20 DEX).
- Ekstraksi string printable, URL, petunjuk class/method, dan kategori fitur.
- Pencarian hasil, laporan JSON/TXT.
- UI Dark Developer, mobile-friendly.

## Batasan penting
Ini adalah **static string triage**, bukan dekompilator penuh. Tidak menghasilkan Smali lengkap, Java hasil JADX, call graph, manifest terurai, atau bukti pasti sebuah fitur aktif. Untuk itu jalankan JADX/Apktool pada backend/container terisolasi. Fungsi Vercel ini punya batas ukuran request, durasi, memori, dan filesystem sementara.

## Deploy
1. Upload folder ini ke GitHub.
2. Import repository di Vercel.
3. Framework preset: Other.
4. Build command: kosongkan; Output Directory: `public`.
5. Deploy. API route ada di `api/analyze.js`.
6. Untuk lokal: `npm install`, lalu `npm run dev`.

## Keamanan
- Batas upload 20 MB dan total ekstraksi DEX 80 MB.
- APK tidak dieksekusi.
- Jangan memproses APK tidak tepercaya pada layanan publik tanpa rate limiting, auth, dan pemantauan biaya.
- Pertimbangkan menambahkan autentikasi, rate limit berbasis IP/user, serta penghapusan file sementara jika kelak memakai penyimpanan.
