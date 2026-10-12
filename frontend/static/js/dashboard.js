/**
 * ScamGuard AI — Interactive Glassmorphism Dashboard Engine
 * Multi-layer telemetry, SVG gauge visualization, and real-time inference.
 */

// ── Tab Navigation ──────────────────────────────────────────
document.querySelectorAll(".nav .nav-item").forEach(item => {
    item.addEventListener("click", () => {
        document.querySelectorAll(".nav .nav-item").forEach(n => n.classList.remove("active"));
        document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));

        item.classList.add("active");
        const tabId = "tab-" + item.dataset.tab;
        const targetTab = document.getElementById(tabId);
        if (targetTab) {
            targetTab.classList.add("active");
        }

        if (item.dataset.tab === "dashboard") loadStats();
        if (item.dataset.tab === "history")   loadHistory();
    });
});

// ── Example Texts (Emoji-Free Professional Scenarios) ────────
const EXAMPLES = [
    "URGENT: Your PayPal account verification is pending. Verify your identity within 2 HOURS or your account access will be terminated immediately. Access your secure link: http://paypal-verify.xyz.tk/login",
    "GUARANTEED 500% returns on crypto asset portfolio within 48 hours. Zero risk automated algorithm. Only 3 investor allocations remaining. Deposit funds now before subscription closes.",
    "Emergency notification: Your dependent has encountered an urgent legal incident overseas. Immediate bail deposit of 800 USD required via prepaid voucher. Do not contact family members directly.",
    "LIMITED ALLOCATION ALERT: You were chosen for priority rewards. Claim window expires in exactly 47 minutes. Confirm payment authorization now before expiration.",
    "FINAL LEGAL NOTICE: Formal warrant pending dispatch. Outstanding tax liabilities require immediate resolution. Contact enforcement desk within 30 minutes to avoid immediate action."
];
let exampleIdx = 0;

document.getElementById("exampleBtn")?.addEventListener("click", () => {
    const input = document.getElementById("contentInput");
    if (input) {
        input.value = EXAMPLES[exampleIdx % EXAMPLES.length];
        exampleIdx++;
        updateCharCount();
        input.focus();
    }
});

document.getElementById("clearBtn")?.addEventListener("click", () => {
    const input = document.getElementById("contentInput");
    if (input) {
        input.value = "";
        updateCharCount();
    }
    const resultCard = document.getElementById("resultCard");
    if (resultCard) {
        resultCard.classList.add("hidden");
    }
});

// ── Character Counter ───────────────────────────────────────
const contentInput = document.getElementById("contentInput");
contentInput?.addEventListener("input", updateCharCount);
function updateCharCount() {
    if (!contentInput) return;
    const len = contentInput.value.length;
    const counter = document.getElementById("charCount");
    if (counter) {
        counter.textContent = len.toLocaleString();
    }
}

// ── Analyze Action ──────────────────────────────────────────
document.getElementById("analyzeBtn")?.addEventListener("click", async () => {
    if (!contentInput) return;
    const content = contentInput.value.trim();
    if (content.length < 5) {
        showToast("Minimum 5 characters required for analysis.", "warn");
        return;
    }

    setAnalyzeLoading(true);

    try {
        const sourceSelect = document.getElementById("sourceSelect");
        const source = sourceSelect ? sourceSelect.value : "unknown";
        const response = await fetch("/api/v1/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content, source })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || "Analysis request failed");
        }

        const result = await response.json();
        displayResult(result);
        showToast("Analysis complete: " + (result.risk_level || "unknown").toUpperCase(), 
                  result.is_scam ? "error" : "success");
    } catch (err) {
        showToast(err.message, "error");
    } finally {
        setAnalyzeLoading(false);
    }
});

function setAnalyzeLoading(loading) {
    const btn = document.getElementById("analyzeBtn");
    const icon = document.getElementById("analyzeIcon");
    const spinner = document.getElementById("analyzeSpinner");
    const text = document.getElementById("analyzeBtnText");

    if (btn) btn.disabled = loading;
    if (icon) icon.classList.toggle("hidden", loading);
    if (spinner) spinner.classList.toggle("hidden", !loading);
    if (text) text.textContent = loading ? "Processing..." : "Analyze";
}

// ── Display Analysis Result ─────────────────────────────────
function displayResult(result) {
    const card = document.getElementById("resultCard");
    if (!card) return;

    card.classList.remove("hidden");

    const risk = (result.risk_level || "safe").toUpperCase();
    const score = Number(result.overall_score || 0);

    // 1. Gauge Needle & Arc Calculation
    // Total semicircle circumference for r=80 is ~251.2
    const totalArc = 251.2;
    const offset = totalArc - (totalArc * Math.min(Math.max(score, 0), 1));
    const gaugeFill = document.getElementById("gaugeFill");
    if (gaugeFill) {
        gaugeFill.style.strokeDashoffset = offset.toFixed(1);
    }

    // Needle rotates from -90deg (0 score) to +90deg (1 score)
    const angle = (score * 180) - 90;
    const needle = document.getElementById("gaugeNeedle");
    if (needle) {
        needle.style.transform = `rotate(${angle.toFixed(1)}deg)`;
    }

    // Gauge Score text
    const gaugeScore = document.getElementById("gaugeScore");
    if (gaugeScore) {
        gaugeScore.textContent = score.toFixed(3);
    }

    // 2. Risk Badge & Subtitle
    const riskBadge = document.getElementById("riskBadge");
    if (riskBadge) {
        riskBadge.textContent = risk;
        riskBadge.className = `risk-badge ${risk}`;
    }

    const riskLabel = document.getElementById("riskLabel");
    if (riskLabel) {
        const descriptions = {
            SAFE: "No malicious time pressure or deceptive vectors detected.",
            LOW: "Minimal urgency cues detected; standard operational context.",
            MEDIUM: "Elevated urgency triggers detected. Verification advised.",
            HIGH: "Severe time manipulation and fraudulent pressure patterns.",
            CRITICAL: "Critical threat: Coercive manipulation and deceptive architecture."
        };
        riskLabel.textContent = descriptions[risk] || "Analysis evaluation finalized.";
    }

    // 3. Processing Time
    const timeBadge = document.getElementById("processingTime");
    if (timeBadge) {
        const ms = result.processing_time_ms ? Number(result.processing_time_ms).toFixed(1) : "0.0";
        timeBadge.textContent = `${ms} ms`;
    }

    // 4. Threat Classification Tags
    const typesContainer = document.getElementById("scamTypesBadges");
    const typesSection = document.getElementById("scamTypesSection");
    if (typesContainer && typesSection) {
        typesContainer.innerHTML = "";
        const types = result.scam_types || [];
        if (types.length > 0) {
            typesSection.classList.remove("hidden");
            types.forEach(typeKey => {
                const tag = document.createElement("span");
                tag.className = "type-tag";
                tag.textContent = typeKey.replace(/_/g, " ").toUpperCase();
                typesContainer.appendChild(tag);
            });
        } else {
            typesSection.classList.add("hidden");
        }
    }

    // 5. Signals List with Visual Severity Meters
    const signalsList = document.getElementById("signalsList");
    const signalsSection = document.getElementById("signalsSection");
    if (signalsList && signalsSection) {
        signalsList.innerHTML = "";
        const signals = result.signals || [];
        if (signals.length > 0) {
            signalsSection.classList.remove("hidden");
            signals.slice(0, 8).forEach(sig => {
                const item = document.createElement("div");
                item.className = "signal-item";

                const severityPct = Math.round((Number(sig.severity || 0.5)) * 100);
                const typeText = (sig.signal_type || "Generic Signal").replace(/_/g, " ").toUpperCase();
                const matchedText = sig.matched_text ? `"${sig.matched_text}"` : "";

                item.innerHTML = `
                    <div class="signal-top">
                        <span class="signal-type">${typeText}</span>
                        <span class="signal-sev">Severity: ${severityPct}%</span>
                    </div>
                    <div class="signal-bar">
                        <div class="signal-bar-fill" style="width: ${severityPct}%;"></div>
                    </div>
                    ${matchedText ? `<div class="signal-text">${matchedText}</div>` : ""}
                `;
                signalsList.appendChild(item);
            });
        } else {
            signalsSection.classList.add("hidden");
        }
    }

    // 6. Actionable Recommendations
    const recsList = document.getElementById("recsList");
    const recsSection = document.getElementById("recsSection");
    if (recsList && recsSection) {
        recsList.innerHTML = "";
        const recs = result.recommendations || [];
        if (recs.length > 0) {
            recsSection.classList.remove("hidden");
            recs.forEach(rec => {
                const cleanText = rec.replace(/[\u{1F600}-\u{1F6FF}|[\u{2600}-\u{26FF}]/gu, "").trim();
                const li = document.createElement("li");
                li.textContent = cleanText || rec;
                recsList.appendChild(li);
            });
        } else {
            recsSection.classList.add("hidden");
        }
    }

    card.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Dashboard Statistics & Charts ───────────────────────────
let riskChartInstance = null;
let activityChartInstance = null;

async function loadStats() {
    try {
        const response = await fetch("/api/v1/stats");
        if (!response.ok) throw new Error("Failed to retrieve statistics");
        const data = await response.json();

        const totalEl = document.getElementById("statTotal");
        const scamsEl = document.getElementById("statScams");
        const safeEl  = document.getElementById("statSafe");
        const rateEl  = document.getElementById("statRate");

        if (totalEl) totalEl.textContent = (data.total_analyzed || 0).toLocaleString();
        if (scamsEl) scamsEl.textContent = (data.scams_detected || 0).toLocaleString();
        if (safeEl)  safeEl.textContent  = (data.safe_content || 0).toLocaleString();
        if (rateEl)  rateEl.textContent  = (data.detection_rate || 0) + "%";

        renderRiskDistribution(data.risk_breakdown || {});
        renderActivityDistribution(data.scams_detected || 0, data.safe_content || 0);
    } catch (err) {
        showToast("Error loading stats: " + err.message, "error");
    }
}

function renderRiskDistribution(breakdown) {
    const canvas = document.getElementById("riskChart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    if (riskChartInstance) riskChartInstance.destroy();

    const keys = ["safe", "low", "medium", "high", "critical"];
    const labels = ["Safe", "Low", "Medium", "High", "Critical"];
    const values = keys.map(k => breakdown[k] || 0);
    const colors = [
        "rgba(0, 230, 118, 0.8)",
        "rgba(255, 193, 7, 0.8)",
        "rgba(255, 109, 0, 0.8)",
        "rgba(255, 23, 68, 0.8)",
        "rgba(179, 0, 30, 0.9)"
    ];

    riskChartInstance = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderColor: "rgba(255, 255, 255, 0.08)",
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#8892aa",
                        font: { family: "system-ui", size: 12 },
                        padding: 14,
                        boxWidth: 12
                    }
                }
            },
            cutout: "70%"
        }
    });
}

function renderActivityDistribution(scams, safe) {
    const canvas = document.getElementById("activityChart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    if (activityChartInstance) activityChartInstance.destroy();

    activityChartInstance = new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["Threats Detected", "Clean Traffic"],
            datasets: [{
                data: [scams, safe],
                backgroundColor: [
                    "rgba(255, 23, 68, 0.65)",
                    "rgba(0, 230, 118, 0.65)"
                ],
                borderColor: [
                    "#ff1744",
                    "#00e676"
                ],
                borderWidth: 1,
                borderRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    ticks: { color: "#8892aa" },
                    grid: { color: "rgba(255, 255, 255, 0.04)" }
                },
                y: {
                    ticks: { color: "#8892aa" },
                    grid: { color: "rgba(255, 255, 255, 0.04)" },
                    beginAtZero: true
                }
            }
        }
    });
}

document.getElementById("refreshStats")?.addEventListener("click", () => {
    loadStats();
    showToast("Telemetry metrics refreshed", "info");
});

// ── Detection History Log ───────────────────────────────────
async function loadHistory() {
    const wrap = document.getElementById("historyTable");
    if (!wrap) return;

    wrap.innerHTML = `
        <div class="loading-state">
            <div class="loading-spinner"></div>
            <span>Synchronizing history...</span>
        </div>`;

    try {
        const response = await fetch("/api/v1/detections/recent?limit=50");
        if (!response.ok) throw new Error("Failed to load logs");
        const data = await response.json();
        const detections = data.detections || [];

        if (detections.length === 0) {
            wrap.innerHTML = `
                <div class="loading-state">
                    <span>No telemetry records logged yet.</span>
                </div>`;
            return;
        }

        let html = `
            <table>
                <thead>
                    <tr>
                        <th>Hash</th>
                        <th>Classification</th>
                        <th>Threat Score</th>
                        <th>Source</th>
                        <th>Threat Vectors</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>`;

        detections.forEach(item => {
            const risk = (item.risk_level || "SAFE").toUpperCase();
            const score = Number(item.overall_score || 0).toFixed(3);
            const vectors = (item.scam_types || []).join(", ").replace(/_/g, " ") || "Standard";
            const timeFormatted = item.timestamp ? new Date(item.timestamp).toLocaleString() : "Unknown";

            html += `
                <tr>
                    <td style="font-family: monospace; font-size: 11px; opacity: 0.8;">${item.content_hash || "—"}</td>
                    <td><span class="tbl-badge ${risk}">${risk}</span></td>
                    <td style="font-variant-numeric: tabular-nums; font-weight: 600;">${score}</td>
                    <td>${item.source || "Unknown"}</td>
                    <td style="font-size: 12px; color: var(--blue);">${vectors}</td>
                    <td style="font-size: 11px; opacity: 0.7;">${timeFormatted}</td>
                </tr>`;
        });

        html += `</tbody></table>`;
        wrap.innerHTML = html;
    } catch (err) {
        wrap.innerHTML = `
            <div class="loading-state">
                <span>Error retrieving logs: ${err.message}</span>
            </div>`;
    }
}

document.getElementById("refreshHistory")?.addEventListener("click", () => {
    loadHistory();
    showToast("History synchronized", "info");
});

// ── Toast Notification System ───────────────────────────────
function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add("fadeout");
        setTimeout(() => toast.remove(), 350);
    }, 3500);
}

// ── Health Check Routine ────────────────────────────────────
(async function initStatus() {
    const dot = document.querySelector("#serverStatus .status-dot");
    const text = document.querySelector("#serverStatus .status-text");

    try {
        const response = await fetch("/api/v1/health");
        const data = await response.json();
        if (data.status === "healthy") {
            if (dot) {
                dot.className = "status-dot online";
            }
            if (text) text.textContent = "Engine Active";
        } else {
            if (dot) dot.className = "status-dot offline";
            if (text) text.textContent = "Degraded";
        }
    } catch {
        if (dot) dot.className = "status-dot offline";
        if (text) text.textContent = "Offline";
    }
})();
