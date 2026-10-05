/**
 * ScamGuard AI — Dashboard JavaScript
 * Handles: tab navigation, analyze API calls, stats, charts, history
 */

// ── Tab Navigation ──────────────────────────────────────────
document.querySelectorAll(".nav-links li").forEach(li => {
    li.addEventListener("click", () => {
        document.querySelectorAll(".nav-links li").forEach(l => l.classList.remove("active"));
        document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
        li.classList.add("active");
        const tabId = "tab-" + li.dataset.tab;
        document.getElementById(tabId)?.classList.add("active");
        if (li.dataset.tab === "dashboard") loadStats();
        if (li.dataset.tab === "history")   loadHistory();
    });
});

// ── Example Scam Texts ──────────────────────────────────────
const EXAMPLES = [
    "🚨 URGENT! Your PayPal account has been compromised! Verify your identity in the next 2 HOURS or your account will be PERMANENTLY SUSPENDED! Click here NOW: http://paypal-verify.xyz.tk/login",
    "GUARANTEED 500% returns on Bitcoin in just 48 hours! Our AI trading bot NEVER loses. Only 3 investment slots left! Invest $500 today and watch it become $3,000 by tomorrow! Act NOW before it's too late!",
    "Mom this is urgent! I got arrested and I'm in jail right now. I need $800 in Google Play gift cards to pay for bail. Please don't tell Dad. Send the card codes to this number immediately!",
    "⏰ COUNTDOWN ALERT: You have been selected as today's winner! Your $10,000 prize expires in exactly 47 minutes! Claim NOW before the timer runs out! This is your FINAL CHANCE!",
    "IRS FINAL NOTICE: Warrant has been issued for your arrest. You owe $3,847 in unpaid taxes. Call 1-800-FAKE-IRS within 30 minutes to avoid immediate arrest. This is not a hoax.",
];
let exampleIdx = 0;

document.getElementById("exampleBtn")?.addEventListener("click", () => {
    document.getElementById("contentInput").value = EXAMPLES[exampleIdx % EXAMPLES.length];
    exampleIdx++;
    updateCharCount();
});

document.getElementById("clearBtn")?.addEventListener("click", () => {
    document.getElementById("contentInput").value = "";
    document.getElementById("resultCard").style.display = "none";
    updateCharCount();
});

// ── Char Counter ────────────────────────────────────────────
const contentInput = document.getElementById("contentInput");
contentInput?.addEventListener("input", updateCharCount);
function updateCharCount() {
    const len = contentInput.value.length;
    document.getElementById("charCount").textContent = len.toLocaleString();
}

// ── Analyze ─────────────────────────────────────────────────
document.getElementById("analyzeBtn")?.addEventListener("click", async () => {
    const content = contentInput.value.trim();
    if (content.length < 5) {
        showToast("Please enter at least 5 characters.", "warn");
        return;
    }

    setAnalyzeLoading(true);

    try {
        const source = document.getElementById("sourceSelect").value;
        const response = await fetch("/api/v1/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content, source })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || "Analysis failed");
        }

        const result = await response.json();
        displayResult(result);
    } catch (err) {
        showToast("Error: " + err.message, "error");
    } finally {
        setAnalyzeLoading(false);
    }
});

function setAnalyzeLoading(loading) {
    document.getElementById("analyzeBtnText").classList.toggle("hidden", loading);
    document.getElementById("analyzeSpinner").classList.toggle("hidden", !loading);
    document.getElementById("analyzeBtn").disabled = loading;
}

function displayResult(result) {
    const card = document.getElementById("resultCard");
    card.style.display = "block";

    // Risk badge
    const risk     = result.risk_level?.toUpperCase() || "SAFE";
    const riskBadge = document.getElementById("riskBadge");
    riskBadge.textContent = `${riskIcon(risk)} ${risk}`;
    riskBadge.className = `risk-badge risk-${risk}`;

    // Score bar
    const pct = Math.round(result.overall_score * 100);
    const fill = document.getElementById("scoreFill");
    fill.style.width = pct + "%";
    fill.style.background = scoreColor(result.overall_score);
    document.getElementById("scoreLabel").textContent = result.overall_score?.toFixed(3);

    // Processing time
    document.getElementById("processingTime").textContent = `⏱ ${result.processing_time_ms?.toFixed(1)}ms`;

    // Scam types
    const typesBadges = document.getElementById("scamTypesBadges");
    typesBadges.innerHTML = "";
    (result.scam_types || []).forEach(t => {
        const span = document.createElement("span");
        span.className = "type-badge";
        span.textContent = t.replace(/_/g, " ");
        typesBadges.appendChild(span);
    });
    document.getElementById("scamTypesSection").style.display =
        result.scam_types?.length ? "block" : "none";

    // Signals
    const signalsList = document.getElementById("signalsList");
    signalsList.innerHTML = "";
    (result.signals || []).slice(0, 8).forEach(s => {
        signalsList.innerHTML += `
            <div class="signal-item">
                <div class="signal-type">⚡ ${s.signal_type?.replace(/_/g, " ")}</div>
                ${s.matched_text ? `<div class="signal-text">"${s.matched_text}"</div>` : ""}
            </div>`;
    });
    document.getElementById("signalsSection").style.display =
        result.signals?.length ? "block" : "none";

    // Recommendations
    const recsList = document.getElementById("recsList");
    recsList.innerHTML = "";
    (result.recommendations || []).forEach(r => {
        const li = document.createElement("li");
        li.textContent = r;
        recsList.appendChild(li);
    });
    document.getElementById("recsSection").style.display =
        result.recommendations?.length ? "block" : "none";

    // Scroll into view
    card.scrollIntoView({ behavior: "smooth", block: "start" });
}

function riskIcon(risk) {
    return { SAFE: "✅", LOW: "🟡", MEDIUM: "🟠", HIGH: "🔴", CRITICAL: "💀" }[risk] || "❓";
}
function scoreColor(score) {
    if (score < 0.2)  return "#2ea043";
    if (score < 0.45) return "#d4a017";
    if (score < 0.65) return "#e3a53d";
    if (score < 0.82) return "#f85149";
    return "#ff1c1c";
}

// ── Stats & Charts ───────────────────────────────────────────
let riskChart, activityChart;

async function loadStats() {
    try {
        const r    = await fetch("/api/v1/stats");
        const data = await r.json();

        document.getElementById("statTotal").textContent = (data.total_analyzed || 0).toLocaleString();
        document.getElementById("statScams").textContent = (data.scams_detected || 0).toLocaleString();
        document.getElementById("statSafe").textContent  = (data.safe_content || 0).toLocaleString();
        document.getElementById("statRate").textContent  = (data.detection_rate || 0) + "%";

        renderRiskChart(data.risk_breakdown || {});
        renderActivityChart(data.scams_detected || 0, data.safe_content || 0);
    } catch (err) {
        console.error("Stats error:", err);
    }
}

function renderRiskChart(breakdown) {
    const ctx = document.getElementById("riskChart")?.getContext("2d");
    if (!ctx) return;
    if (riskChart) riskChart.destroy();

    const labels = Object.keys(breakdown);
    const values = Object.values(breakdown);
    const colors = { safe: "#2ea043", low: "#d4a017", medium: "#e3a53d", high: "#f85149", critical: "#ff1c1c" };

    riskChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
            datasets: [{ data: values, backgroundColor: labels.map(l => colors[l] || "#58a6ff"), borderWidth: 0 }]
        },
        options: {
            plugins: { legend: { labels: { color: "#c9d1d9" } } },
            responsive: true
        }
    });
}

function renderActivityChart(scams, safe) {
    const ctx = document.getElementById("activityChart")?.getContext("2d");
    if (!ctx) return;
    if (activityChart) activityChart.destroy();

    activityChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["Scams Detected", "Safe Content"],
            datasets: [{
                data: [scams, safe],
                backgroundColor: ["rgba(248,81,73,0.7)", "rgba(46,160,67,0.7)"],
                borderColor: ["#f85149", "#2ea043"],
                borderWidth: 1, borderRadius: 6
            }]
        },
        options: {
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: "#8b949e" }, grid: { color: "#21262d" } },
                y: { ticks: { color: "#8b949e" }, grid: { color: "#21262d" } }
            },
            responsive: true
        }
    });
}

document.getElementById("refreshStats")?.addEventListener("click", loadStats);

// ── History ──────────────────────────────────────────────────
async function loadHistory() {
    const wrap = document.getElementById("historyTable");
    wrap.innerHTML = "<p class='loading-msg'>Loading...</p>";

    try {
        const r    = await fetch("/api/v1/detections/recent?limit=50");
        const data = await r.json();
        const dets = data.detections || [];

        if (!dets.length) {
            wrap.innerHTML = "<p class='loading-msg'>No detections yet. Run some analyses first!</p>";
            return;
        }

        let html = `<table>
            <thead><tr>
                <th>#</th><th>Risk</th><th>Score</th><th>Source</th>
                <th>Scam Types</th><th>Timestamp</th>
            </tr></thead><tbody>`;

        dets.forEach(d => {
            const risk = d.risk_level?.toUpperCase() || "SAFE";
            html += `<tr>
                <td style="color:#8b949e;font-size:11px;">${d.content_hash}</td>
                <td><span class="risk-badge risk-${risk}" style="padding:2px 8px;font-size:11px;">${riskIcon(risk)} ${risk}</span></td>
                <td style="font-family:monospace;">${(d.overall_score||0).toFixed(3)}</td>
                <td>${d.source || "—"}</td>
                <td style="font-size:11px;color:#58a6ff;">${(d.scam_types||[]).join(", ") || "—"}</td>
                <td style="color:#8b949e;font-size:11px;">${new Date(d.timestamp).toLocaleString()}</td>
            </tr>`;
        });

        html += "</tbody></table>";
        wrap.innerHTML = html;
    } catch (err) {
        wrap.innerHTML = `<p class='loading-msg'>Error loading history: ${err.message}</p>`;
    }
}

document.getElementById("refreshHistory")?.addEventListener("click", loadHistory);

// ── Toast Notifications ──────────────────────────────────────
function showToast(message, type = "info") {
    const toast = document.createElement("div");
    toast.style.cssText = `
        position:fixed;bottom:24px;right:24px;z-index:9999;
        padding:12px 20px;border-radius:8px;font-size:14px;
        background:${type === "error" ? "#f85149" : type === "warn" ? "#e3a53d" : "#2ea043"};
        color:white;font-weight:600;box-shadow:0 4px 20px rgba(0,0,0,0.4);
        animation:fadeIn 0.3s ease;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3500);
}

// ── Health Check on Load ─────────────────────────────────────
(async () => {
    try {
        const r    = await fetch("/api/v1/health");
        const data = await r.json();
        const dot  = document.getElementById("serverStatus");
        dot.textContent  = "● " + (data.status === "healthy" ? "Online" : "Degraded");
        dot.style.color  = data.status === "healthy" ? "#2ea043" : "#f85149";
    } catch {
        document.getElementById("serverStatus").textContent = "● Offline";
        document.getElementById("serverStatus").style.color = "#f85149";
    }
})();
