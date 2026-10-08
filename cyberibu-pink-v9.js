
window.addEventListener("load", async () => {
  try {
    if ("serviceWorker" in navigator) {
      const regs = await navigator.serviceWorker.getRegistrations();
      for (const reg of regs) await reg.unregister();
    }
    if ("caches" in window) {
      const keys = await caches.keys();
      for (const key of keys) {
        if (key.toLowerCase().includes("cyberibu")) await caches.delete(key);
      }
    }
  } catch (_) {}
});

const STATE_KEY = "cyberibu_v3_state";

const state = JSON.parse(localStorage.getItem(STATE_KEY) || "{}");
state.answers ??= Array(6).fill(null);
state.score ??= null;
state.checks ??= Array(8).fill(false);
state.emergency ??= 0;

function saveState(){
  localStorage.setItem(STATE_KEY, JSON.stringify(state));
}

function escapeHtml(value){
  return String(value)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

// ---------------- URL CHECKER ----------------
// V5: works both with VS Code Live Server (local analysis) and Node backend.
// If backend is available, CyberIbu will enrich the local result with server reputation data.

const suspiciousKeywordsBrowser = [
  "login","verify","verification","secure","security","update","account","akun",
  "hadiah","gift","bonus","claim","redeem","bank","wallet","otp","password",
  "confirm","konfirmasi","blocked","suspended","urgent","invoice","payment",
  "refund","pin","dana","ovo","gopay","shopee","tokopedia"
];

const shortenersBrowser = new Set([
  "bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rb.gy","shorturl.at","s.id",
  "rebrand.ly","ow.ly","tiny.one","buff.ly"
]);

const riskyTldsBrowser = new Set([
  "zip","mov","top","click","work","support","rest","cam","tk","gq","cf","ml"
]);

function normalizeBrowserUrl(raw){
  const input = String(raw || "").trim();
  if(!input) throw new Error("Masukkan URL terlebih dahulu.");
  if(input.length > 2048) throw new Error("URL terlalu panjang.");

  const withScheme = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(input)
    ? input
    : `https://${input}`;

  const parsed = new URL(withScheme);
  if(!["http:","https:"].includes(parsed.protocol)){
    throw new Error("Hanya URL http/https yang dapat diperiksa.");
  }
  return parsed;
}

function isIPv4Browser(host){
  if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return false;
  return host.split(".").every(n => Number(n) >= 0 && Number(n) <= 255);
}

function browserLocalAnalysis(raw){
  const parsed = normalizeBrowserUrl(raw);
  const findings = [];
  const tags = new Set();
  let score = 0;

  const host = parsed.hostname.toLowerCase();
  const full = parsed.href.toLowerCase();
  const parts = host.split(".").filter(Boolean);
  const subdomains = Math.max(0, parts.length - 2);
  const tld = parts.length ? parts[parts.length - 1] : "";

  if(parsed.protocol !== "https:"){
    score += 12;
    findings.push("Link tidak menggunakan HTTPS.");
  }else{
    findings.push("Link menggunakan HTTPS, tetapi HTTPS saja tidak membuktikan situs aman.");
  }

  if(isIPv4Browser(host)){
    score += 24;
    tags.add("phishing");
    findings.push("Tujuan menggunakan alamat IP langsung, bukan nama domain biasa.");
  }

  if(host.includes("xn--")){
    score += 28;
    tags.add("phishing");
    findings.push("Domain menggunakan punycode (xn--), yang dapat dipakai untuk menyerupai nama domain lain.");
  }

  if(subdomains >= 3){
    score += Math.min(18, subdomains * 4);
    tags.add("phishing");
    findings.push(`Domain memiliki ${subdomains} subdomain dan lebih sulit dibaca.`);
  }

  if(raw.includes("@")){
    score += 18;
    tags.add("phishing");
    findings.push("URL mengandung karakter @ yang dapat membingungkan tujuan sebenarnya.");
  }

  if(parsed.port && !["80","443"].includes(parsed.port)){
    score += 9;
    findings.push(`URL menggunakan port tidak umum (${parsed.port}).`);
  }

  if(shortenersBrowser.has(host)){
    score += 20;
    tags.add("short-link");
    findings.push("Link memakai layanan pemendek URL sehingga tujuan akhirnya tersembunyi.");
  }

  if(riskyTldsBrowser.has(tld)){
    score += 8;
    findings.push(`Domain menggunakan akhiran .${tld}; perlu pemeriksaan tambahan.`);
  }

  const keywordHits = suspiciousKeywordsBrowser.filter(k => full.includes(k));
  if(keywordHits.length){
    score += Math.min(24, keywordHits.length * 5);
    tags.add("phishing");
    tags.add("scam");
    findings.push(`URL memuat kata sensitif/urgensi: ${keywordHits.slice(0,6).join(", ")}.`);
  }

  if(raw.length > 120){
    score += 9;
    findings.push("URL sangat panjang sehingga tujuan sebenarnya lebih sulit diperiksa secara visual.");
  }

  const encoded = (raw.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if(encoded >= 3){
    score += 8;
    findings.push("URL memiliki banyak karakter yang di-encode.");
  }

  if((host.match(/-/g) || []).length >= 3){
    score += 7;
    findings.push("Domain menggunakan banyak tanda hubung.");
  }

  if(/\.(apk|exe|scr|bat|cmd|msi|jar|ps1|vbs)(\?|#|$)/i.test(parsed.pathname)){
    score += 32;
    tags.add("malware-download");
    findings.push("URL tampak mengarah langsung ke file executable/aplikasi yang berpotensi berisiko.");
  }

  if(/(\bfree\b|\bhadiah\b|\bbonus\b|\bclaim\b|\brefund\b)/i.test(full)){
    tags.add("scam");
  }

  score = Math.min(100, score);

  let classification = "Tidak ditemukan indikasi kuat";
  if(tags.has("malware-download")){
    classification = "Indikasi download berisiko";
  }else if(tags.has("phishing") && tags.has("scam")){
    classification = "Indikasi phishing / penipuan";
  }else if(tags.has("phishing")){
    classification = "Indikasi phishing";
  }else if(tags.has("scam")){
    classification = "Indikasi penipuan";
  }else if(tags.has("short-link")){
    classification = "Short-link perlu diperiksa";
  }else if(score >= 30){
    classification = "Link perlu diwaspadai";
  }

  const recommendations = [];
  if(score >= 60){
    recommendations.push("Jangan buka atau login melalui link ini sebelum tujuan diverifikasi.");
    recommendations.push("Jangan memasukkan password, OTP, PIN, data kartu, atau informasi identitas.");
    recommendations.push("Jika mengatasnamakan bank/marketplace, buka aplikasi resminya secara manual.");
  }else if(score >= 30){
    recommendations.push("Periksa ejaan domain dan identitas pengirim melalui kanal lain.");
    recommendations.push("Hindari login atau transaksi langsung dari link yang dikirim melalui chat/SMS.");
  }else{
    recommendations.push("Tidak ditemukan banyak indikator struktural berisiko.");
    recommendations.push("Tetap verifikasi konteks pengirim dan nama domain sebelum membuka link.");
  }

  if(tags.has("short-link")){
    recommendations.push("Minta pengirim memberikan alamat website asli, bukan short-link.");
  }
  if(tags.has("malware-download")){
    recommendations.push("Jangan mengunduh atau menjalankan APK/EXE/script dari sumber yang belum diverifikasi.");
  }
  recommendations.push("Hasil pemeriksaan adalah indikator risiko, bukan jaminan absolut bahwa situs aman.");

  const level = score >= 60 ? "high" : score >= 30 ? "medium" : "low";
  const levelLabel = score >= 60 ? "RISIKO TINGGI" : score >= 30 ? "PERLU WASPADA" : "RISIKO RENDAH";

  return {
    hostname: parsed.hostname,
    normalizedUrl: parsed.href,
    score,
    classification,
    level,
    levelLabel,
    findings,
    recommendations,
    virusTotal:{
      available:false,
      note:"Mode lokal: analisis struktur URL dilakukan langsung di browser. Jalankan node server.js untuk mengaktifkan pemeriksaan backend/VirusTotal."
    }
  };
}

async function tryBackendCheck(raw){
  try{
    const response = await fetch(`${window.location.origin}/api/check-url`,{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({url:raw}),
      cache:"no-store"
    });

    const contentType = response.headers.get("content-type") || "";

    if(!response.ok){
      let message = "Backend tidak dapat memeriksa URL.";
      if(contentType.includes("application/json")){
        try{
          const err = await response.json();
          if(err?.error) message = err.error;
        }catch(_){}
      }
      throw new Error(message);
    }

    if(!contentType.includes("application/json")){
      throw new Error("Backend tidak mengembalikan JSON.");
    }

    return await response.json();
  }catch(err){
    console.warn("CyberIbu backend unavailable, fallback ke mode lokal:", err.message);
    return null;
  }
}

async function checkUrl(raw){
  const input = String(raw || "").trim();
  if(!input){
    alert("Tempel link yang ingin diperiksa terlebih dahulu.");
    return;
  }

  const loading = document.getElementById("loadingBox");
  const result = document.getElementById("resultBox");
  loading.classList.remove("hidden");
  result.classList.add("hidden");

  try{
    // Always calculate a safe local result first.
    const localResult = browserLocalAnalysis(input);

    // Try backend only when one is actually available.
    const backendResult = await tryBackendCheck(input);

    renderUrlResult(backendResult || localResult);
  }catch(err){
    alert(err.message || "Link tidak dapat dianalisis.");
  }finally{
    loading.classList.add("hidden");
  }
}

function renderUrlResult(data){
  document.getElementById("resultBox").classList.remove("hidden");
  document.getElementById("classification").textContent = data.classification;
  document.getElementById("riskScore").textContent = `${data.score}/100`;
  document.getElementById("riskBar").style.width = `${data.score}%`;
  document.getElementById("hostname").textContent = data.hostname;

  const badge = document.getElementById("riskBadge");
  badge.className = "status-pill " + data.level;
  badge.textContent = data.levelLabel;

  document.getElementById("findingsList").innerHTML =
    data.findings.map(x=>`<li>${escapeHtml(x)}</li>`).join("");
  document.getElementById("recommendationsList").innerHTML =
    data.recommendations.map(x=>`<li>${escapeHtml(x)}</li>`).join("");

  // Multi-risk classification
  const tags = new Set(data.tags || []);
  const vt = data.virusTotal || {};
  const vtStats = vt.stats || {};

  const phishingDetected =
    tags.has("phishing") ||
    /phishing/i.test(data.classification || "") ||
    (vt.phishingHits || 0) > 0;

  const scamDetected =
    tags.has("scam") ||
    /penipuan|scam/i.test(data.classification || "");

  const malwareDetected =
    tags.has("malware-download") ||
    /malware|berbahaya|download berisiko/i.test(data.classification || "") ||
    (vt.malwareHits || 0) > 0 ||
    (vtStats.malicious || 0) > 0;

  const categoryBox = document.getElementById("riskCategories");
  if(categoryBox){
    categoryBox.innerHTML = `
      <div class="risk-mini-card ${phishingDetected ? "detected" : "clear"}">
        <span>Phishing</span>
        <strong>${phishingDetected ? "TERINDIKASI" : "Tidak terindikasi"}</strong>
      </div>
      <div class="risk-mini-card ${scamDetected ? "detected" : "clear"}">
        <span>Scam / Penipuan</span>
        <strong>${scamDetected ? "TERINDIKASI" : "Tidak terindikasi"}</strong>
      </div>
      <div class="risk-mini-card ${malwareDetected ? "detected" : "clear"}">
        <span>Malware</span>
        <strong>${malwareDetected ? "TERINDIKASI" : "Belum terdeteksi"}</strong>
      </div>
      <div class="risk-mini-card ${vt.available ? "external" : "neutral"}">
        <span>VirusTotal</span>
        <strong>${vt.available ? "AKTIF" : "Belum ada laporan"}</strong>
      </div>
    `;
  }

  const vtBox = document.getElementById("vtBox");
  vtBox.classList.remove("hidden");

  if(vt.available){
    const s = vt.stats || {};
    document.getElementById("vtSummary").textContent =
      `VirusTotal aktif · ${s.malicious || 0} malicious · ${s.suspicious || 0} suspicious · ${s.harmless || 0} harmless`;
    document.getElementById("vtNote").textContent =
      vt.note || "Reputasi eksternal tersedia.";
  }else{
    document.getElementById("vtSummary").textContent = "Belum ada laporan eksternal";
    document.getElementById("vtNote").textContent =
      vt.note || "Hasil saat ini berdasarkan analisis struktur URL.";
  }

  document.getElementById("resultBox").scrollIntoView({
    behavior:"smooth",
    block:"center"
  });
}

document.getElementById("checkBtn").addEventListener("click",()=>{
  checkUrl(document.getElementById("urlInput").value);
});

document.getElementById("urlInput").addEventListener("keydown",e=>{
  if(e.key==="Enter") document.getElementById("checkBtn").click();
});

document.getElementById("heroCheckBtn").addEventListener("click",()=>{
  const value = document.getElementById("heroUrlInput").value;
  document.getElementById("urlInput").value = value;
  document.getElementById("cek-link").scrollIntoView({behavior:"smooth"});
  setTimeout(()=>checkUrl(value),250);
});

document.getElementById("heroUrlInput").addEventListener("keydown",e=>{
  if(e.key==="Enter") document.getElementById("heroCheckBtn").click();
});

// ---------------- ASSESSMENT ----------------
const questions = [
  {
    q:"Jika seseorang mengaku dari bank meminta OTP, apa yang Ibu lakukan?",
    options:[
      ["Memberikan OTP jika dia tahu nama saya",0],
      ["Tidak memberikan OTP dan menghubungi kanal resmi bank",17],
      ["Memberikan beberapa digit saja",2]
    ]
  },
  {
    q:"Bagaimana penggunaan password untuk akun penting?",
    options:[
      ["Password berbeda/unik untuk akun penting",17],
      ["Satu password untuk hampir semua akun",0],
      ["Password sederhana agar mudah diingat",3]
    ]
  },
  {
    q:"Ada file UNDANGAN.apk dikirim melalui WhatsApp. Apa yang dilakukan?",
    options:[
      ["Install untuk melihat undangan",0],
      ["Jangan install dan verifikasi pengirim melalui jalur lain",17],
      ["Teruskan ke keluarga agar diperiksa",2]
    ]
  },
  {
    q:"Apakah 2FA/verifikasi dua langkah aktif di akun penting?",
    options:[
      ["Ya, minimal pada email/WhatsApp/akun penting",17],
      ["Belum tahu apa itu 2FA",0],
      ["Pernah aktif tetapi dimatikan",3]
    ]
  },
  {
    q:"Nomor baru mengaku anak/saudara lalu minta transfer mendesak. Apa yang Ibu lakukan?",
    options:[
      ["Transfer sedikit dulu",0],
      ["Verifikasi lewat nomor lama atau anggota keluarga lain",16],
      ["Tanya nama lengkap di chat",4]
    ]
  },
  {
    q:"Saat pesan membuat panik dan meminta klik link, langkah pertama adalah...",
    options:[
      ["Klik agar masalah cepat selesai",0],
      ["Berhenti, cek sumber, lalu buka aplikasi resmi secara manual",16],
      ["Teruskan ke grup keluarga",3]
    ]
  }
];

let qIndex = 0;
function renderQuestion(){
  const q = questions[qIndex];
  document.getElementById("qCounter").textContent = `Pertanyaan ${qIndex+1} dari ${questions.length}`;
  const pct = Math.round(((qIndex+1)/questions.length)*100);
  document.getElementById("qPercent").textContent = `${pct}%`;
  document.getElementById("qBar").style.width = `${pct}%`;
  document.getElementById("questionText").textContent = q.q;

  const wrap = document.getElementById("answerOptions");
  wrap.innerHTML = "";
  q.options.forEach((opt,i)=>{
    const b=document.createElement("button");
    b.className="answer" + (state.answers[qIndex]===i ? " selected":"");
    b.textContent=opt[0];
    b.onclick=()=>{
      state.answers[qIndex]=i;
      saveState();
      renderQuestion();
    };
    wrap.appendChild(b);
  });

  document.getElementById("prevQ").disabled = qIndex===0;
  document.getElementById("nextQ").textContent = qIndex===questions.length-1 ? "Lihat Hasil":"Berikutnya";
}
function calculateAssessment(){
  let total=0;
  state.answers.forEach((a,i)=>{
    if(a!==null) total += questions[i].options[a][1];
  });
  state.score=Math.min(100,total);
  saveState();
  renderAssessmentScore();
}
function renderAssessmentScore(){
  const s=state.score;
  document.getElementById("assessmentScore").textContent=s===null?"--":`${s}/100`;
  let label="Belum dinilai", advice="Selesaikan self-check untuk mendapatkan rekomendasi.";
  if(s!==null && s>=80){label="Kebiasaan cukup aman";advice="Pertahankan 2FA, password unik, dan kebiasaan verifikasi link."}
  else if(s!==null && s>=60){label="Masih perlu diperkuat";advice="Prioritaskan 2FA, password unik, dan verifikasi sebelum klik."}
  else if(s!==null){label="Perlu perhatian";advice="Mulai dari OTP, 2FA, password, dan jangan instal APK dari chat."}
  document.getElementById("assessmentLabel").textContent=label;
  document.getElementById("assessmentAdvice").textContent=advice;
}
document.getElementById("prevQ").onclick=()=>{if(qIndex>0){qIndex--;renderQuestion()}};
document.getElementById("nextQ").onclick=()=>{
  if(state.answers[qIndex]===null){alert("Pilih jawaban terlebih dahulu.");return;}
  if(qIndex<questions.length-1){qIndex++;renderQuestion()}
  else if(state.answers.every(x=>x!==null)){calculateAssessment()}
};

// ---------------- CHECKLIST ----------------
const checks = [
  ["Aktifkan 2FA WhatsApp","Tambahkan PIN dan email pemulihan jika tersedia."],
  ["Periksa Linked Devices","Keluar dari perangkat yang tidak dikenal."],
  ["Gunakan password unik","Jangan satu password untuk seluruh akun."],
  ["Aktifkan 2FA email","Email sering menjadi pintu pemulihan akun lain."],
  ["Jangan bagikan OTP/PIN","Termasuk kepada orang yang mengaku petugas."],
  ["Aplikasi dari store resmi","Hindari APK yang dikirim lewat chat."],
  ["Aktifkan lock screen/biometrik","Kurangi risiko saat HP hilang atau dipinjam."],
  ["Simpan kanal resmi bank/platform","Gunakan hanya nomor dan aplikasi resmi saat insiden."]
];
function renderChecks(){
  const grid=document.getElementById("checklistGrid");
  grid.innerHTML="";
  checks.forEach((item,i)=>{
    const label=document.createElement("label");
    label.className="check-item";
    label.innerHTML=`<input type="checkbox" ${state.checks[i]?"checked":""}>
      <span><strong>${escapeHtml(item[0])}</strong><small>${escapeHtml(item[1])}</small></span>`;
    label.querySelector("input").onchange=e=>{
      state.checks[i]=e.target.checked;saveState();renderCheckSummary();
    };
    grid.appendChild(label);
  });
  renderCheckSummary();
}
function renderCheckSummary(){
  const done=state.checks.filter(Boolean).length;
  document.getElementById("checkSummary").textContent=`${done} dari ${checks.length} selesai`;
  document.getElementById("checkBar").style.width=`${Math.round(done/checks.length*100)}%`;
}

// ---------------- EMERGENCY ----------------
const emergencies=[
  ["WhatsApp dibajak",[
    "Coba login kembali menggunakan nomor telepon sendiri.",
    "Jangan berikan OTP kepada siapa pun.",
    "Setelah akses kembali, periksa dan keluarkan perangkat tertaut yang tidak dikenal.",
    "Beri tahu keluarga bahwa akun sempat disalahgunakan.",
    "Gunakan pusat bantuan resmi WhatsApp jika pemulihan gagal."
  ]],
  ["Klik link mencurigakan",[
    "Jangan masukkan password, OTP, PIN, atau data kartu.",
    "Tutup halaman dan jangan mengunduh file yang ditawarkan.",
    "Jika sudah memasukkan password, segera ganti melalui aplikasi/website resmi.",
    "Aktifkan 2FA dan periksa aktivitas login.",
    "Jika data finansial sudah dimasukkan, hubungi bank melalui kanal resmi."
  ]],
  ["Salah transfer",[
    "Simpan bukti transfer, chat, nomor rekening, dan kronologi.",
    "Segera hubungi bank melalui kanal resmi.",
    "Jangan mengirim dana tambahan walau pelaku menjanjikan pengembalian.",
    "Laporkan melalui kanal resmi yang sesuai.",
    "Amankan akun bila pelaku mengetahui data login atau informasi pribadi."
  ]],
  ["HP hilang",[
    "Gunakan fitur pencarian perangkat dari akun Android/iOS jika aktif.",
    "Ganti password email utama dari perangkat aman.",
    "Hubungi operator untuk mengamankan SIM jika diperlukan.",
    "Hubungi bank jika mobile banking berisiko diakses.",
    "Beri tahu kontak dekat bila akun chat berpotensi disalahgunakan."
  ]]
];
function renderEmergency(){
  const tabs=document.getElementById("emergencyTabs");
  tabs.innerHTML="";
  emergencies.forEach((e,i)=>{
    const b=document.createElement("button");
    b.className="tab"+(state.emergency===i?" active":"");
    b.textContent=e[0];
    b.onclick=()=>{state.emergency=i;saveState();renderEmergency()};
    tabs.appendChild(b);
  });
  const item=emergencies[state.emergency];
  document.getElementById("emergencyPanel").innerHTML=`
    <h3>${escapeHtml(item[0])}</h3>
    ${item[1].map((x,i)=>`<div class="step"><span>${i+1}</span><p>${escapeHtml(x)}</p></div>`).join("")}
  `;
}

// ---------------- MOBILE NAV ----------------
document.getElementById("menuBtn").onclick=()=>document.getElementById("navMenu").classList.toggle("open");
document.querySelectorAll(".nav-links a").forEach(a=>a.onclick=()=>document.getElementById("navMenu").classList.remove("open"));

renderQuestion();
renderAssessmentScore();
renderChecks();
renderEmergency();
