import { unzipSync } from "fflate";

const MAX_FILE_BYTES = 50 * 1024 * 1024;
const MAX_TOTAL_UNCOMPRESSED = 80 * 1024 * 1024;
const MAX_DEX_COUNT = 20;
const MAX_STRINGS = 50000;

const utf8 = new TextDecoder("utf-8", { fatal: false });

function json(status, data) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    }
  });
}

function printableStrings(bytes, limit = MAX_STRINGS) {
  const out = [];
  let run = [];
  const flush = () => {
    if (run.length >= 4 && out.length < limit) {
      const s = utf8.decode(new Uint8Array(run)).trim();
      if (s && /[A-Za-z0-9]/.test(s)) out.push(s);
    }
    run = [];
  };
  for (let i = 0; i < bytes.length && out.length < limit; i++) {
    const b = bytes[i];
    if (b >= 32 && b <= 126) run.push(b);
    else if (b >= 0xC2 && b <= 0xF4) {
      // Preserve valid UTF-8 sequences when possible.
      let j = i, n = b < 0xE0 ? 2 : b < 0xF0 ? 3 : 4;
      const seq = [b];
      while (seq.length < n && j + 1 < bytes.length && (bytes[j + 1] & 0xC0) === 0x80) seq.push(bytes[++j]);
      if (seq.length === n) run.push(...seq);
      else flush();
      i = j;
    } else flush();
  }
  flush();
  return [...new Set(out)];
}

function dexSummary(name, bytes) {
  const strings = printableStrings(bytes);
  const classNames = new Set();
  const methodHints = new Set();
  const all = strings.join("\n");
  for (const s of strings) {
    if (/^L[a-zA-Z0-9_$/-]+;?$/.test(s) && s.includes("/")) classNames.add(s);
    if (/^[A-Za-z_$][\w$]{2,80}$/.test(s) &&
        /(redeem|activate|verify|validate|generate|create|login|register|fetch|request|build|decode|encrypt|decrypt|save|load|delete|update|check|claim|purchase|subscribe|token|license|voucher|coupon|key|code)/i.test(s)) {
      methodHints.add(s);
    }
  }
  const keywordGroups = {
    "Redeem / Aktivasi": /\bredeem\b|activation|activate|license|voucher|coupon|claim/i,
    "API / Jaringan": /https?:\/\/|retrofit|okhttp|HttpURLConnection|WebSocket|graphql|api[_/-]/i,
    "Database": /SQLite|RoomDatabase|CREATE TABLE|SELECT\s+.+\s+FROM|SharedPreferences|DataStore/i,
    "Login / Akun": /login|sign.?in|register|password|username|oauth|authentication/i,
    "Pembayaran": /billing|purchase|subscription|payment|checkout|qris|transaction/i,
    "WebView": /WebView|loadUrl|addJavascriptInterface|shouldOverrideUrlLoading/i,
    "Kriptografi": /Cipher|MessageDigest|SecretKey|AES|RSA|Base64|encrypt|decrypt/i,
    "Izin / Perangkat": /android\.permission\.|getDeviceId|ANDROID_ID|READ_SMS|AccessibilityService/i
  };
  const findings = Object.entries(keywordGroups).map(([label, re]) => ({
    label, matches: strings.filter(s => re.test(s)).slice(0, 30),
    count: strings.filter(s => re.test(s)).length
  })).filter(x => x.count > 0);
  const urls = [...new Set((all.match(/https?:\/\/[^\s"'<>\\]{4,240}/g) || []))].slice(0, 100);
  return {
    name,
    bytes: bytes.length,
    stringsCount: strings.length,
    strings: strings.slice(0, 2500),
    classHints: [...classNames].slice(0, 500),
    methodHints: [...methodHints].slice(0, 500),
    findings,
    urls
  };
}

export default async function handler(req) {
  if (req.method !== "POST") return json(405, { error: "Gunakan POST multipart/form-data." });
  const origin = req.headers.get("origin");
  const host = req.headers.get("host");
  if (origin) {
    try {
      const u = new URL(origin);
      if (host && u.host !== host) return json(403, { error: "Origin tidak diizinkan." });
    } catch { return json(403, { error: "Origin tidak valid." }); }
  }

  let form;
  try { form = await req.formData(); }
  catch { return json(400, { error: "Form upload tidak valid." }); }
  const file = form.get("apk");
  if (!file || typeof file.arrayBuffer !== "function") return json(400, { error: "Pilih file APK terlebih dahulu." });
  if (!file.name.toLowerCase().endsWith(".apk")) return json(400, { error: "File harus berakhiran .apk." });
  if (file.size < 8 || file.size > MAX_FILE_BYTES) {
    return json(413, { error: `Ukuran APK harus 8 byte sampai ${MAX_FILE_BYTES / 1024 / 1024} MB.` });
  }

  let bytes;
  try { bytes = new Uint8Array(await file.arrayBuffer()); }
  catch { return json(400, { error: "Gagal membaca file." }); }
  if (bytes[0] !== 0x50 || bytes[1] !== 0x4b) return json(400, { error: "Header ZIP/APK tidak valid." });

  let entries;
  try { entries = unzipSync(bytes, { filter: f => !f.name.startsWith("/") && !f.name.split("/").includes("..") }); }
  catch { return json(400, { error: "APK/ZIP rusak atau tidak dapat dibaca." }); }

  const dexNames = Object.keys(entries)
    .filter(n => /^classes(?:\d+)?\.dex$/i.test(n))
    .sort((a, b) => {
      const num = s => Number((s.match(/^classes(\d*)\.dex$/i) || [,""])[1] || 1);
      return num(a) - num(b);
    });
  if (!dexNames.length) return json(422, { error: "Tidak menemukan classes.dex. APK mungkin bukan APK Android biasa atau DEX berada dalam format yang tidak didukung." });
  if (dexNames.length > MAX_DEX_COUNT) return json(413, { error: `Ditemukan ${dexNames.length} DEX; batas versi ini ${MAX_DEX_COUNT}.` });

  let total = 0;
  const dexReports = [];
  for (const name of dexNames) {
    const dex = entries[name];
    total += dex.length;
    if (total > MAX_TOTAL_UNCOMPRESSED) return json(413, { error: "Total ukuran DEX hasil ekstraksi melebihi batas aman 80 MB." });
    dexReports.push(dexSummary(name, dex));
  }

  const strings = dexReports.flatMap(d => d.strings.map(value => ({ dex: d.name, value })));
  const combined = strings.map(x => x.value).join("\n");
  const urls = [...new Set(dexReports.flatMap(d => d.urls))];
  const permissions = [...new Set(combined.match(/android\.permission\.[A-Z0-9_]+/g) || [])];
  const packageCandidates = [...new Set(combined.match(/L[a-zA-Z0-9_]+(?:\/[a-zA-Z0-9_$-]+){2,};/g) || [])].slice(0, 200);
  const allFindings = {};
  for (const d of dexReports) for (const f of d.findings) {
    if (!allFindings[f.label]) allFindings[f.label] = { label: f.label, count: 0, examples: [] };
    allFindings[f.label].count += f.count;
    allFindings[f.label].examples.push(...f.matches.map(value => ({ dex: d.name, value })));
  }
  for (const f of Object.values(allFindings)) f.examples = f.examples.slice(0, 60);

  const report = {
    fileName: file.name.slice(0, 120),
    fileSize: file.size,
    scannedAt: new Date().toISOString(),
    dexCount: dexReports.length,
    dexFiles: dexReports.map(d => ({ name: d.name, bytes: d.bytes, stringsCount: d.stringsCount, classHints: d.classHints.length, methodHints: d.methodHints.length })),
    totalDexBytes: total,
    urls,
    permissions,
    packageCandidates,
    findings: Object.values(allFindings),
    dexReports,
    notes: [
      "Ini analisis statis berbasis string yang diekstrak dari DEX, bukan dekompilasi Smali lengkap.",
      "Nama class/method bisa tidak tersedia atau berubah karena obfuscation.",
      "String yang ditemukan belum tentu kode aktif; konfirmasi dengan alur pemanggilan dan analisis JADX/Apktool."
    ]
  };
  return json(200, report);
}
