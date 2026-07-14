var API_BASE = "http://localhost:5050";
var currentData = null;

// start scanning target nd update page....
async function startAnalysis() {
  var inputEl = document.getElementById("target-input");
  var input = inputEl.value.trim();
  if (input === "") {
    showError("Please enter a domain or URL to analyze.");
    return;
  }

  hideError();
  setLoading(true);
  showPipeline();
  hideResults();
  resetSteps();
  setStep("recon", "active", "Scanning...");

  try {
    var resp = await fetch(API_BASE + "/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: input })
    });

    if (resp.status !== 200 && !resp.ok) {
      throw new Error("Server returned error status " + resp.status);
    }

    var data = await resp.json();
    currentData = data;

    updateSteppers(data.stages);
    renderResults(data);
    switchTab('vuln');
    showResults();

  } catch (err) {
    setStep("recon", "error", "Failed");
    showError("Analysis failed: " + err.message + ". Is the backend running on port 5050?");
  } finally {
    setLoading(false);
  }
}

document.getElementById("target-input").addEventListener("keydown", function(e) {
  if (e.key === "Enter") {
    startAnalysis();
  }
});

var STEP_ORDER = ["recon", "vuln", "bron", "compliance"];
var STAGE_MAP = {
  recon: "recon",
  vulnerability: "vuln",
  bron: "bron",
  compliance: "compliance",
};

// reset steps status to blank....
function resetSteps() {
  // loop steps to clear styles....
  for (var i = 0; i < STEP_ORDER.length; i++) {
    setStep(STEP_ORDER[i], "", "");
  }
}

// set step status text nd style class....
function setStep(stepId, state, statusText) {
  var el = document.getElementById("step-" + stepId);
  if (!el) return;
  el.className = "step " + state;
  el.querySelector(".step-status").textContent = statusText;
}

// update all step visual status check....
function updateSteppers(stages) {
  if (!stages) return;
  
  var keys = Object.keys(STAGE_MAP);
  // loop stage keys to check status done or fail....
  for (var i = 0; i < keys.length; i++) {
    var stageKey = keys[i];
    var stepId = STAGE_MAP[stageKey];
    var stage = stages[stageKey];
    if (stage) {
      if (stage.status === "done") {
        setStep(stepId, "done", "✓ Done");
      } else if (stage.status === "error") {
        setStep(stepId, "error", "✗ Error");
      }
    }
  }
}

// draw the dashboard scorecards nd panels....
function renderResults(data) {
  var stages = {};
  if (data && data.stages) {
    stages = data.stages;
  }
  
  var complianceData = null;
  if (stages.compliance && stages.compliance.data) {
    complianceData = stages.compliance.data;
  }
  
  var vulnData = null;
  if (stages.vulnerability && stages.vulnerability.data) {
    vulnData = stages.vulnerability.data;
  }

  renderScoreCards(complianceData);
  renderVulnPanel(vulnData);
  renderCompliancePanel(complianceData);
}

// draw score card numbers for overview....
function renderScoreCards(compliance) {
  var container = document.getElementById("score-cards");
  container.innerHTML = "";

  var vulnData = null;
  if (currentData && currentData.stages && currentData.stages.vulnerability) {
    vulnData = currentData.stages.vulnerability.data;
  }

  var overallVal = "N/A";
  if (compliance && compliance.scores && compliance.scores.overall !== undefined) {
    overallVal = compliance.scores.overall;
  }

  var cveVal = 0;
  if (vulnData && vulnData.total_cves !== undefined) {
    cveVal = vulnData.total_cves;
  }

  var headerVal = "N/A";
  if (compliance && compliance.scores && compliance.scores.security_headers !== undefined) {
    headerVal = Math.round(compliance.scores.security_headers);
  }

  var cards = [
    {
      label: "Overall Score",
      value: overallVal,
      suffix: overallVal !== "N/A" ? "%" : "",
      color: scoreColor(overallVal),
    },
    {
      label: "CVEs Found",
      value: cveVal,
      suffix: "",
      color: cveVal > 10 ? "score-bad" : (cveVal > 3 ? "score-warn" : "score-good"),
    },
    {
      label: "Security Headers",
      value: headerVal,
      suffix: headerVal !== "N/A" ? "%" : "",
      color: scoreColor(headerVal),
    },
  ];

  // loop scorecard array to render each box....
  for (var i = 0; i < cards.length; i++) {
    var card = cards[i];
    var el = document.createElement("div");
    el.className = "score-card";
    el.innerHTML = '<div class="score-value ' + card.color + '">' + card.value + card.suffix + '</div>' +
                   '<div class="score-label">' + card.label + '</div>';
    container.appendChild(el);
  }
}

// get colored class by score value....
function scoreColor(val) {
  if (val == null || val === "N/A") return "score-warn";
  if (val >= 70) return "score-good";
  if (val >= 40) return "score-warn";
  return "score-bad";
}

// draw cve summary card nd details list....
function renderVulnPanel(vuln) {
  var container = document.getElementById("vuln-content");
  if (!vuln) {
    container.innerHTML = emptyState("No vulnerability data");
    return;
  }

  var cves = [];
  if (vuln.cves) {
    cves = vuln.cves;
  }

  var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  // loop cves to count severity statistics....
  for (var i = 0; i < cves.length; i++) {
    var cve = cves[i];
    var sev = "UNKNOWN";
    if (cve.severity) {
      sev = cve.severity.toUpperCase();
    }
    if (counts[sev] !== undefined) {
      counts[sev]++;
    } else {
      counts.UNKNOWN++;
    }
  }

  var severitySummaryHtml = 
    '<div class="vuln-summary-row">' +
      '<div class="vuln-summary-card sev-CRITICAL">' +
        '<div class="count">' + counts.CRITICAL + '</div>' +
        '<div class="label">Critical</div>' +
      '</div>' +
      '<div class="vuln-summary-card sev-HIGH">' +
        '<div class="count">' + counts.HIGH + '</div>' +
        '<div class="label">High</div>' +
      '</div>' +
      '<div class="vuln-summary-card sev-MEDIUM">' +
        '<div class="count">' + counts.MEDIUM + '</div>' +
        '<div class="label">Medium</div>' +
      '</div>' +
      '<div class="vuln-summary-card sev-LOW">' +
        '<div class="count">' + counts.LOW + '</div>' +
        '<div class="label">Low</div>' +
      '</div>' +
    '</div>';

  var cvesHtml = "";
  if (cves.length > 0) {
    // loop cves array to build list html items....
    for (var j = 0; j < cves.length; j++) {
      var cve = cves[j];
      
      var techVersionHtml = "";
      if (cve.tech_version) {
        techVersionHtml = '<span class="cve-tech-tag">v' + cve.tech_version + '</span>';
      }

      var cwesHtml = "";
      if (cve.cwes && cve.cwes.length > 0) {
        cwesHtml += '<div class="cwe-tags">';
        // loop cwe strings of cve to add badges....
        for (var k = 0; k < cve.cwes.length; k++) {
          cwesHtml += '<span class="cwe-tag">' + cve.cwes[k] + '</span>';
        }
        cwesHtml += '</div>';
      }

      cvesHtml += 
        '<div class="cve-card sev-' + cve.severity + '">' +
          '<div class="cve-header">' +
            '<span class="cve-id"><a href="' + cve.nvd_url + '" target="_blank">' + cve.cve_id + '</a></span>' +
            '<span class="sev-badge sev-' + cve.severity + '">' + cve.severity + '</span>' +
            '<span class="cvss-score">CVSS ' + cve.cvss_score + '</span>' +
            '<span class="cve-tech-tag">' + escapeHtml(cve.tech) + '</span>' +
            techVersionHtml +
          '</div>' +
          '<div class="cve-desc">' + escapeHtml(cve.description) + '</div>' +
          cwesHtml +
        '</div>';
    }
  } else {
    cvesHtml = "<div class='empty-state'><p>No CVEs found for detected technologies.</p></div>";
  }

  var errorHtml = "";
  if (vuln.errors && vuln.errors.length > 0) {
    errorHtml += '<div class="card error-border">';
    errorHtml += '<div class="card-title text-danger"><span>⚠️</span> Lookup Errors</div>';
    // loop errors to print lists....
    for (var e = 0; e < vuln.errors.length; e++) {
      errorHtml += '<div class="error-item">' + escapeHtml(vuln.errors[e]) + '</div>';
    }
    errorHtml += '</div>';
  }

  container.innerHTML = 
    '<div class="card">' +
      '<div class="card-title"><span>📊</span> Severity Summary</div>' +
      severitySummaryHtml +
    '</div>' +
    '<div class="card">' +
      '<div class="card-title"><span>⚠️</span> CVEs (' + cves.length + ' total, sorted by severity)</div>' +
      '<div class="cve-list">' + cvesHtml + '</div>' +
    '</div>' +
    errorHtml;
}

// draw compliance lists for nist, cis nd owasp....
function renderCompliancePanel(compliance) {
  var container = document.getElementById("compliance-content");
  if (!compliance) {
    container.innerHTML = emptyState("No compliance data");
    return;
  }

  var nist = compliance.nist_800_53 || [];
  var cis = compliance.cis_controls || [];
  var owasp = compliance.owasp_top10 || [];
  var headers = compliance.security_headers || [];
  var scores = compliance.scores || {};

  var nistScore   = scores.nist_compliance !== undefined ? Math.round(scores.nist_compliance) : 0;
  var cisScore    = scores.cis_compliance !== undefined ? Math.round(scores.cis_compliance) : 0;
  var owaspScore  = scores.owasp_compliance !== undefined ? Math.round(scores.owasp_compliance) : 0;
  var headerScore = scores.security_headers !== undefined ? Math.round(scores.security_headers) : 0;
  var overall     = scores.overall !== undefined ? Math.round(scores.overall) : 0;

  // build overall summary bar at top....
  var summaryHtml =
    '<div class="report-summary">' +
      '<div class="report-overall">' +
        '<div class="report-overall-score" style="color:' + scoreHex(overall) + '">' + overall + '%</div>' +
        '<div class="report-overall-label">Overall Compliance Score</div>' +
        '<div class="report-overall-bar"><div class="report-bar-fill" style="width:' + overall + '%;background:' + scoreHex(overall) + '"></div></div>' +
      '</div>' +
      '<div class="report-scores-row">' +
        makeScoreBlock("NIST 800-53", nistScore) +
        makeScoreBlock("CIS Controls", cisScore) +
        makeScoreBlock("OWASP Top 10", owaspScore) +
        makeScoreBlock("Sec. Headers", headerScore) +
      '</div>' +
    '</div>';

  // nist report card section....
  var nistHtml = makeReportCard(
    "NIST SP 800-53",
    "Controls Triggered",
    nistScore,
    nist.length,
    nist,
    function(c) {
      return makeTableRow(c.control, c.description, c.triggered_by.join(", "), "TRIGGERED");
    }
  );

  // cis report card section....
  var cisHtml = makeReportCard(
    "CIS Controls",
    "Controls Triggered",
    cisScore,
    cis.length,
    cis,
    function(c) {
      return makeTableRow(c.control, c.description, c.triggered_by.join(", "), "TRIGGERED");
    }
  );

  // owasp report card section....
  var owaspHtml = makeReportCard(
    "OWASP Top 10",
    "Categories Triggered",
    owaspScore,
    owasp.length,
    owasp,
    function(o) {
      return makeTableRow(o.id, o.name, o.triggered_by_cwes.join(", "), "TRIGGERED");
    }
  );

  // security headers report card section....
  var passCount = 0;
  for (var i = 0; i < headers.length; i++) {
    if (headers[i].status === "PASS") passCount++;
  }
  var headerRowsHtml = "";
  // loop headers to build table rows....
  for (var j = 0; j < headers.length; j++) {
    var h = headers[j];
    var val = h.status === "PASS" ? escapeHtml(h.value || "") : "Not Set";
    headerRowsHtml += makeTableRow(h.header, val, "", h.status);
  }
  var headerCardHtml =
    '<div class="report-card">' +
      '<div class="report-card-header">' +
        '<div class="report-card-title">Security Headers</div>' +
        '<div class="report-card-meta">' + passCount + " / " + headers.length + " Passed</div>" +
        '<div class="report-card-bar-wrap">' +
          '<div class="report-card-bar"><div class="report-bar-fill" style="width:' + headerScore + '%;background:' + scoreHex(headerScore) + '"></div></div>' +
          '<span class="report-card-pct" style="color:' + scoreHex(headerScore) + '">' + headerScore + '%</span>' +
        '</div>' +
      '</div>' +
      '<table class="report-table">' +
        '<thead><tr><th>Header</th><th>Value</th><th>Status</th></tr></thead>' +
        '<tbody>' + headerRowsHtml + '</tbody>' +
      '</table>' +
    '</div>';

  container.innerHTML = summaryHtml + nistHtml + cisHtml + owaspHtml + headerCardHtml;
}

// build a single report card block....
function makeReportCard(title, metaLabel, score, count, items, rowFn) {
  var rowsHtml = "";
  if (items.length > 0) {
    // loop items to render rows....
    for (var i = 0; i < items.length; i++) {
      rowsHtml += rowFn(items[i]);
    }
  } else {
    rowsHtml = '<tr><td colspan="4" class="report-clear">✓ No ' + title + ' violations found</td></tr>';
  }
  return (
    '<div class="report-card">' +
      '<div class="report-card-header">' +
        '<div class="report-card-title">' + title + '</div>' +
        '<div class="report-card-meta">' + count + " " + metaLabel + "</div>" +
        (score > 0 ?
          '<div class="report-card-bar-wrap">' +
            '<div class="report-card-bar"><div class="report-bar-fill" style="width:' + score + '%;background:' + scoreHex(score) + '"></div></div>' +
            '<span class="report-card-pct" style="color:' + scoreHex(score) + '">' + score + '%</span>' +
          '</div>'
        : "") +
      '</div>' +
      '<table class="report-table">' +
        '<thead><tr><th>Control ID</th><th>Description</th><th>Triggered By</th><th>Status</th></tr></thead>' +
        '<tbody>' + rowsHtml + '</tbody>' +
      '</table>' +
    '</div>'
  );
}

// build a single table row with status badge....
function makeTableRow(id, desc, trigger, status) {
  var badgeClass = status === "PASS" ? "badge-pass" : (status === "TRIGGERED" ? "badge-triggered" : "badge-fail");
  return (
    '<tr>' +
      '<td><span class="ctrl-id">' + escapeHtml(id) + '</span></td>' +
      '<td>' + escapeHtml(desc) + '</td>' +
      '<td class="report-trigger">' + escapeHtml(trigger) + '</td>' +
      '<td><span class="report-badge ' + badgeClass + '">' + status + '</span></td>' +
    '</tr>'
  );
}

// build a score block in summary row....
function makeScoreBlock(label, score) {
  return (
    '<div class="report-score-block">' +
      '<div class="report-score-val" style="color:' + scoreHex(score) + '">' + score + '%</div>' +
      '<div class="report-score-label">' + label + '</div>' +
      '<div class="report-score-bar"><div class="report-bar-fill" style="width:' + score + '%;background:' + scoreHex(score) + '"></div></div>' +
    '</div>'
  );
}

// switch active tabs nd content panels....
function switchTab(name) {
  var tabs = document.querySelectorAll(".tab");
  // loop tabs to remove active styles....
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].classList.remove("active");
  }

  var panels = document.querySelectorAll(".panel");
  // loop panels to hide content....
  for (var j = 0; j < panels.length; j++) {
    panels[j].classList.remove("active");
  }

  document.getElementById("tab-" + name).classList.add("active");
  document.getElementById("panel-" + name).classList.add("active");
}

// disable buttons during fetching....
function setLoading(on) {
  var btn = document.getElementById("analyze-btn");
  var btnText = document.getElementById("btn-text");
  var spinner = document.getElementById("btn-spinner");
  
  btn.disabled = on;
  btnText.textContent = on ? "Analyzing..." : "Analyze";
  if (on) {
    spinner.classList.remove("hidden");
  } else {
    spinner.classList.add("hidden");
  }
}

// show scanning animation bar....
function showPipeline() {
  document.getElementById("pipeline-section").classList.remove("hidden");
}

// hide results panel block....
function hideResults() {
  document.getElementById("results-section").classList.add("hidden");
}

// show results panel block....
function showResults() {
  document.getElementById("results-section").classList.remove("hidden");
}

// show warning error banner msg....
function showError(msg) {
  var banner = document.getElementById("error-banner");
  document.getElementById("error-message").textContent = msg;
  banner.classList.remove("hidden");
}

// hide warning error banner msg....
function hideError() {
  document.getElementById("error-banner").classList.add("hidden");
}

// render blank warning states....
function emptyState(msg) {
  return '<div class="empty-state">' +
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">' +
      '<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>' +
    '</svg>' +
    '<p>' + msg + '</p>' +
  '</div>';
}

// escape html chars to prevent injection....
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// get clean score hex color tag....
function scoreHex(score) {
  if (score == null) return "#6b7694";
  if (score >= 70) return "#27c98a";
  if (score >= 40) return "#f5a524";
  return "#f04060";
}
