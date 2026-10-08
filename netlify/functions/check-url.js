const { URL } = require("url");

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

  // URL userinfo (contoh https://nama@domain.tld) dapat menyesatkan.
  // Jangan menandai '@' yang hanya muncul di query/path biasa.
  if (parsed.username || parsed.password) {
    score += 18; tags.add("phishing");
    findings.push("URL memiliki informasi pengguna sebelum domain yang dapat membingungkan tujuan sebenarnya.");
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
  return Buffer.from(text, "utf8").toString("base64").replace(/=+$/,"" ).replace(/\+/g,"-").replace(/\//g,"_");
}

async function vtLookup(urlString) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY || "";
  if (!apiKey) {
    return { available:false, note:"VirusTotal belum dikonfigurasi pada server." };
  }

  try {
    const id = base64Url(urlString);
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { "x-apikey": apiKey, "accept":"application/json" }
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

function jsonResponse(statusCode, obj) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    },
    body: JSON.stringify(obj)
  };
}

exports.handler = async function(event) {
  if (event.httpMethod !== "POST") {
    return jsonResponse(405, { error: "Method not allowed" });
  }

  try {
    if ((event.body || "").length > 10000) {
      return jsonResponse(413, { error: "Request terlalu besar." });
    }

    const payload = JSON.parse(event.body || "{}");
    const parsed = normalizeInput(payload.url);
    const local = localAnalysis(parsed, payload.url);
    const vt = await vtLookup(parsed.href);
    const combined = combine(local, vt);
    const recommendations = buildRecommendations(combined.score, local.tags, vt);

    return jsonResponse(200, {
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
    return jsonResponse(400, { error: e.message || "URL tidak valid." });
  }
};
