/**
 * PhishExplain — popup.js
 *
 * Extracts the visible text of the active tab, sends it to the local
 * FastAPI backend at http://127.0.0.1:8000/analyze, and renders the
 * structured results in the popup.
 */

const BACKEND_URL = "http://127.0.0.1:8000/analyze";

// ── DOM references ───────────────────────────────────────────────────────────
const analyzeBtn     = document.getElementById("analyzeBtn");
const btnLabel       = document.getElementById("btnLabel");
const spinner        = document.getElementById("spinner");
const errorBox       = document.getElementById("errorBox");
const errorText      = document.getElementById("errorText");
const resultsEl      = document.getElementById("results");
const finalScoreEl   = document.getElementById("finalScore");
const riskBadgeEl    = document.getElementById("riskBadge");
const scoreBarEl     = document.getElementById("scoreBar");
const aiScoreEl      = document.getElementById("aiScore");
const heuristicScoreEl = document.getElementById("heuristicScore");
const summaryTextEl  = document.getElementById("summaryText");

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Show/hide the loading state on the button */
function setLoading(loading) {
  if (loading) {
    btnLabel.classList.add("hidden");
    spinner.classList.remove("hidden");
    analyzeBtn.disabled = true;
  } else {
    btnLabel.classList.remove("hidden");
    spinner.classList.add("hidden");
    analyzeBtn.disabled = false;
  }
}

/** Display an error message and hide results */
function showError(msg) {
  errorText.textContent = msg;
  errorBox.classList.remove("hidden");
  resultsEl.classList.add("hidden");
}

/** Hide the error box */
function clearError() {
  errorBox.classList.add("hidden");
}

/**
 * Render the analysis results returned by the backend.
 * @param {Object} data  — parsed JSON from /analyze
 */
function renderResults(data) {
  const score = Math.round(data.final_score ?? 0);
  const level = (data.risk_level ?? "unknown").toLowerCase();

  // ── Score number (colour matches risk level) ─────────────────────
  finalScoreEl.textContent = score;
  finalScoreEl.className = `score-num score-${level}`;

  // ── Risk badge ───────────────────────────────────────────────────
  riskBadgeEl.textContent = `${data.risk_level ?? "Unknown"} Risk`;
  riskBadgeEl.className   = `badge badge-${level}`;

  // ── Sub-scores ───────────────────────────────────────────────────
  aiScoreEl.textContent        = Math.round(data.ai_score ?? 0);
  heuristicScoreEl.textContent = Math.round(data.heuristic_score ?? 0);

  // ── Threat Summary ───────────────────────────────────────────────
  const summary = data.summary ?? "No summary available.";
  summaryTextEl.textContent = summary.length > 300
    ? summary.slice(0, 297) + "…"
    : summary;

  // ── Show results ─────────────────────────────────────────────────
  clearError();
  resultsEl.classList.remove("hidden");

  // ── Animate score bar ────────────────────────────────────────────
  // Reset to 0 first so the transition always plays from the left,
  // regardless of any previous value.  The rAF + timeout gives the
  // browser one paint cycle to render the reset before animating.
  scoreBarEl.className   = `bar bar-${level}`;
  scoreBarEl.style.width = "0%";
  requestAnimationFrame(() => {
    setTimeout(() => {
      scoreBarEl.style.width = `${score}%`;
    }, 30);
  });
}

// ── Main click handler ────────────────────────────────────────────────────────

analyzeBtn.addEventListener("click", async () => {
  setLoading(true);
  clearError();
  resultsEl.classList.add("hidden");

  try {
    // 1. Get the active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.id) {
      showError("Unable to access the current tab.");
      return;
    }

    // 2. Inject a script into the active tab to read its visible text
    let injectionResults;
    try {
      injectionResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          // Collapse whitespace to keep the payload reasonably compact
          return (document.body?.innerText ?? "").replace(/\s+/g, " ").trim();
        }
      });
    } catch (injectionErr) {
      // Scripting blocked on chrome://, extension pages, PDFs, etc.
      showError(
        "Cannot read this page. Try on a regular website (e.g. Gmail, Outlook Web, a news article)."
      );
      return;
    }

    const pageText = injectionResults?.[0]?.result ?? "";

    if (!pageText) {
      showError("This page appears to have no readable text.");
      return;
    }

    // Limit payload to ~8 000 chars (≈ 2 000 tokens) to keep inference fast
    const content = pageText.slice(0, 8000);

    // 3. Send to local backend
    let response;
    try {
      response = await fetch(BACKEND_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content })
      });
    } catch (networkErr) {
      showError(
        "Cannot reach backend. Make sure the PhishExplain server is running:\n" +
        "uvicorn main:app --reload  (in the backend folder)"
      );
      return;
    }

    if (!response.ok) {
      showError(`Backend returned an error (HTTP ${response.status}).`);
      return;
    }

    const data = await response.json();
    renderResults(data);

  } finally {
    setLoading(false);
  }
});
