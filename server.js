const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const ROOT = __dirname;

// Load simple .env without external package.
const envPath = path.join(ROOT, ".env");
if (fs.existsSync(envPath)) {
  const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim().replace(/^['"]|['"]$/g, "");
    if (!process.env[key]) process.env[key] = value;
  }
}

const PORT = process.env.PORT || 8000;
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || "";

const suspiciousKeywords = [
  "login","verify","verification","secure","security","update","account","akun",
  "hadiah","gift","bonus","claim","redeem","bank","wallet","otp","password",
  "confirm","konfirmasi","blocked","suspended","urgent","invoice","payment",
  "refund","pin","dana","ovo","gopay","shopee","tokopedia"
];

const shorteners = new Set([
  "bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rb.gy","shorturl.at","s.id",
  "rebrand.ly","ow.ly","tiny.one","buff.ly"
]);

const riskyTlds = new Set(["zip","mov","top","click","work","support","rest","cam","tk","gq","cf","ml"]);

function normalizeInput(raw) {
  const input = String(raw || "").trim();
  if (!input) throw new Error("Masukkan URL terlebih dahulu.");
  if (input.length > 2048) throw new Error("URL terlalu panjang.");
  const withScheme = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(input) ? input : `https://${input}`;
  const parsed = new URL(withScheme);
  if (!["http:","https:"].includes(parsed.protocol)) throw new Error("Hanya URL http/https yang dapat diperiksa.");
  return parsed;
}

function isIPv4(host) {
  const m = host.match(/^(\d{1,3}\.){3}\d{1,3}$/);
  if (!m) return false;
  return host.split(".").every(n => Number(n) >= 0 && Number(n) <= 255);
}

function localAnalysis(parsed, raw) {
  const findings = [];
  const tags = new Set();
  let score = 0;
  const host = parsed.hostname.toLowerCase();
  const full = parsed.href.toLowerCase();
  const parts = host.split(".").filter(Boolean);
  const subdomains = Math.max(0, parts.length - 2);
  const tld = parts.at(-1) || "";

  if (parsed.protocol !== "https:") {
    score += 12;
    findings.push("Link tidak menggunakan HTTPS.");
  } else {
    findings.push("Link menggunakan HTTPS, tetapi HTTPS saja tidak membuktikan situs aman.");
  }

  if (isIPv4(host)) {
    score += 24; tags.add("phishing");
    findings.push("Tujuan menggunakan alamat IP langsung, bukan nama domain biasa.");
  }

  if (host.includes("xn--")) {
    score += 28; tags.add("phishing");
    findings.push("Domain menggunakan punycode (xn--), yang dapat dipakai untuk menyerupai nama domain lain.");
  }

  if (subdomains >= 3) {
    score += Math.min(18, subdomains * 4); tags.add("phishing");
    findings.push(`Domain memiliki ${subdomains} subdomain dan lebih sulit dibaca.`);
  }

  if (raw.includes("@")) {
    score += 18; tags.add("phishing");
    findings.push("URL mengandung karakter @ yang dapat membingungkan pembaca tentang tujuan sebenarnya.");
  }

  if (parsed.port && !["80","443"].includes(parsed.port)) {
    score += 9;
    findings.push(`URL menggunakan port tidak umum (${parsed.port}).`);
  }

  if (shorteners.has(host)) {
    score += 20; tags.add("short-link");
    findings.push("Link memakai layanan pemendek URL sehingga tujuan akhirnya tidak terlihat dari teks link.");
  }

  if (riskyTlds.has(tld)) {
    score += 8;
    findings.push(`Domain menggunakan akhiran .${tld}; perlu pemeriksaan tambahan.`);
  }

  const keywordHits = suspiciousKeywords.filter(k => full.includes(k));
  if (keywordHits.length) {
    score += Math.min(24, keywordHits.length * 5);
    tags.add("phishing");
    tags.add("scam");
    findings.push(`URL memuat kata sensitif/urgensi: ${keywordHits.slice(0,6).join(", ")}.`);
  }

  if (raw.length > 120) {
    score += 9;
    findings.push("URL sangat panjang sehingga tujuan sebenarnya lebih sulit diperiksa secara visual.");
  }

  const encoded = (raw.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (encoded >= 3) {
    score += 8;
    findings.push("URL memiliki banyak karakter yang di-encode.");
  }

  if ((host.match(/-/g) || []).length >= 3) {
    score += 7;
    findings.push("Domain menggunakan banyak tanda hubung.");
  }

  if (/\.(apk|exe|scr|bat|cmd|msi|jar|ps1|vbs)(\?|#|$)/i.test(parsed.pathname)) {
    score += 32; tags.add("malware-download");
    findings.push("URL tampak mengarah langsung ke file executable/aplikasi yang berpotensi berisiko.");
  }

  if (/(\bfree\b|\bhadiah\b|\bbonus\b|\bclaim\b|\brefund\b)/i.test(full)) {
    tags.add("scam");
  }

  score = Math.min(100, score);

  let classification = "Tidak ditemukan indikasi kuat";
  if (tags.has("malware-download")) classification = "Indikasi download berisiko";
  else if (tags.has("phishing") && tags.has("scam")) classification = "Indikasi phishing / penipuan";
  else if (tags.has("phishing")) classification = "Indikasi phishing";
  else if (tags.has("scam")) classification = "Indikasi penipuan";
  else if (tags.has("short-link")) classification = "Short-link perlu diperiksa";
  else if (score >= 30) classification = "Link perlu diwaspadai";

  return { score, findings, tags:[...tags], classification };
}

function buildRecommendations(score, tags, vt) {
  const rec = [];
  const malicious = vt?.stats?.malicious || 0;
  const suspicious = vt?.stats?.suspicious || 0;

  if (malicious > 0 || suspicious > 0 || score >= 60) {
    rec.push("Jangan buka atau login melalui link ini sebelum tujuan diverifikasi.");
    rec.push("Jangan memasukkan password, OTP, PIN, data kartu, atau informasi identitas.");
    rec.push("Jika link mengatasnamakan bank/marketplace, buka aplikasi resminya secara manual.");
  } else if (score >= 30) {
    rec.push("Periksa ejaan domain dan identitas pengirim melalui kanal lain.");
    rec.push("Hindari login atau transaksi langsung dari link yang dikirim melalui chat/SMS.");
  } else {
    rec.push("Tidak ditemukan banyak indikator struktural berisiko.");
    rec.push("Tetap verifikasi konteks pengirim dan nama domain sebelum membuka link.");
  }

  if (tags.includes("short-link")) rec.push("Minta pengirim memberikan alamat website asli, bukan short-link.");
  if (tags.includes("malware-download")) rec.push("Jangan mengunduh atau menjalankan file APK/EXE/script dari sumber yang belum diverifikasi.");
  rec.push("Hasil pemeriksaan adalah indikator risiko, bukan jaminan absolut bahwa situs aman.");
  return [...new Set(rec)];
}

function base64Url(text) {
  return Buffer.from(text, "utf8").toString("base64").replace(/=+$/,"").replace(/\+/g,"-").replace(/\//g,"_");
}

async function vtLookup(urlString) {
  if (!VT_API_KEY) {
    return { available:false, note:"VirusTotal belum dikonfigurasi. Tambahkan VIRUSTOTAL_API_KEY di file .env untuk reputasi eksternal." };
  }

  try {
    const id = base64Url(urlString);
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { "x-apikey": VT_API_KEY, "accept":"application/json" }
    });

    if (res.status === 404) {
      return { available:false, note:"URL belum memiliki laporan VirusTotal yang tersedia. CyberIbu tidak otomatis mengirim URL baru demi menjaga privasi." };
    }
    if (!res.ok) {
      return { available:false, note:`VirusTotal tidak dapat digunakan saat ini (HTTP ${res.status}).` };
    }

    const json = await res.json();
    const attrs = json?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const results = attrs.last_analysis_results || {};

    const names = Object.values(results)
      .filter(x => x && x.result)
      .map(x => String(x.result).toLowerCase());

    const phishingHits = names.filter(x => x.includes("phish")).length;
    const malwareHits = names.filter(x => /malware|malicious|trojan|virus/.test(x)).length;

    return {
      available:true,
      stats,
      phishingHits,
      malwareHits,
      note:"Reputasi berasal dari laporan URL VirusTotal yang sudah tersedia."
    };
  } catch (e) {
    return { available:false, note:"Terjadi kendala saat mengakses reputasi VirusTotal." };
  }
}

function combine(local, vt) {
  let score = local.score;
  let classification = local.classification;
  const findings = [...local.findings];

  if (vt?.available) {
    const malicious = vt.stats?.malicious || 0;
    const suspicious = vt.stats?.suspicious || 0;

    if (malicious > 0) {
      score = Math.max(score, Math.min(100, 65 + malicious * 4));
      findings.push(`${malicious} engine VirusTotal menandai URL sebagai malicious.`);
      classification = vt.phishingHits > 0 ? "Terdeteksi phishing oleh reputasi keamanan" : "Terdeteksi berbahaya oleh reputasi keamanan";
    } else if (suspicious > 0) {
      score = Math.max(score, 55);
      findings.push(`${suspicious} engine VirusTotal menandai URL sebagai suspicious.`);
      if (classification === "Tidak ditemukan indikasi kuat") classification = "Reputasi eksternal mencurigakan";
    } else {
      findings.push("Laporan VirusTotal yang tersedia tidak menunjukkan deteksi malicious pada analisis terakhir.");
    }

    if (vt.malwareHits > 0 && vt.phishingHits === 0) classification = "Indikasi malware / URL berbahaya";
  }

  score = Math.min(100, score);
  const level = score >= 60 ? "high" : score >= 30 ? "medium" : "low";
  const levelLabel = score >= 60 ? "RISIKO TINGGI" : score >= 30 ? "PERLU WASPADA" : "RISIKO RENDAH";

  return { score, classification, findings, level, levelLabel };
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type":"application/json; charset=utf-8",
    "Content-Length":Buffer.byteLength(body),
    "Cache-Control":"no-store"
  });
  res.end(body);
}

function serveFile(req, res) {
  let pathname = new URL(req.url, `http://${req.headers.host}`).pathname;
  if (pathname === "/") pathname = "/index.html";

  const filePath = path.normalize(path.join(ROOT, pathname));
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403); res.end("Forbidden"); return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const types = {
    ".html":"text/html; charset=utf-8",
    ".css":"text/css; charset=utf-8",
    ".js":"application/javascript; charset=utf-8",
    ".svg":"image/svg+xml",
    ".json":"application/json; charset=utf-8"
  };

  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    res.writeHead(200, {
      "Content-Type": types[ext] || "application/octet-stream",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Pragma": "no-cache",
      "Expires": "0"
    });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "POST" && req.url === "/api/check-url") {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 10000) req.destroy();
    });

    req.on("end", async () => {
      try {
        const payload = JSON.parse(body || "{}");
        const parsed = normalizeInput(payload.url);
        const local = localAnalysis(parsed, payload.url);
        const vt = await vtLookup(parsed.href);
        const combined = combine(local, vt);
        const recommendations = buildRecommendations(combined.score, local.tags, vt);

        sendJson(res, 200, {
          hostname: parsed.hostname,
          normalizedUrl: parsed.href,
          score: combined.score,
          classification: combined.classification,
          level: combined.level,
          levelLabel: combined.levelLabel,
          findings: combined.findings,
          recommendations,
          tags: local.tags || [],
          virusTotal: vt
        });
      } catch (e) {
        sendJson(res, 400, { error: e.message || "URL tidak valid." });
      }
    });
    return;
  }

  if (req.method === "GET") {
    serveFile(req, res);
    return;
  }

  res.writeHead(405); res.end("Method not allowed");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`CyberIbu berjalan di http://localhost:${PORT}`);
  console.log(VT_API_KEY ? "VirusTotal: aktif" : "VirusTotal: belum aktif (mode analisis lokal)");
});
