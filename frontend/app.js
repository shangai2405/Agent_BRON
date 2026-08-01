var API_BASE = "http://localhost:5050";
var currentData = null;

var USERS = {
  "admin": "bron123",
  "user": "pass123"
};

// check if user already logged in on page load....
window.addEventListener("load", function() {
  var loggedIn = sessionStorage.getItem("bron_user");
  if (loggedIn) {
    showApp(loggedIn);
  }
});

// handle login button click....
function doLogin() {
  var username = document.getElementById("login-user").value.trim();
  var password = document.getElementById("login-pass").value;
  var errEl = document.getElementById("login-error");

  if (USERS[username] && USERS[username] === password) {
    errEl.classList.add("hidden");
    sessionStorage.setItem("bron_user", username);
    showApp(username);
  } else {
    errEl.classList.remove("hidden");
  }
}

// allow pressing enter in password field....
document.addEventListener("DOMContentLoaded", function() {
  var passInput = document.getElementById("login-pass");
  if (passInput) {
    passInput.addEventListener("keydown", function(e) {
      if (e.key === "Enter") doLogin();
    });
  }
});

// show main app nd hide login page....
function showApp(username) {
  document.getElementById("login-page").classList.add("hidden");
  document.getElementById("app-page").classList.remove("hidden");
  document.getElementById("profile-username").textContent = username;
  document.getElementById("dropdown-name").textContent = username;
  setGreeting(username);
}

// sign out nd go back to login page....
function doSignOut() {
  sessionStorage.removeItem("bron_user");
  document.getElementById("app-page").classList.add("hidden");
  document.getElementById("login-page").classList.remove("hidden");
  document.getElementById("login-user").value = "";
  document.getElementById("login-pass").value = "";
  document.getElementById("profile-dropdown").classList.add("hidden");
}

// toggle show hide profile dropdown....
function toggleProfileMenu() {
  var dd = document.getElementById("profile-dropdown");
  if (dd.classList.contains("hidden")) {
    dd.classList.remove("hidden");
  } else {
    dd.classList.add("hidden");
  }
}

// close dropdown when clicking outside....
document.addEventListener("click", function(e) {
  var wrap = document.getElementById("profile-menu-wrap") || document.querySelector(".profile-menu-wrap");
  var dd = document.getElementById("profile-dropdown");
  if (dd && wrap && !wrap.contains(e.target)) {
    dd.classList.add("hidden");
  }
});

// set greeting text based on time of day....
function setGreeting(username) {
  var hour = new Date().getHours();
  var greet = "";
  if (hour >= 5 && hour < 12) {
    greet = "Good morning, " + username + "!";
  } else if (hour >= 12 && hour < 17) {
    greet = "Good afternoon, " + username + "!";
  } else if (hour >= 17 && hour < 21) {
    greet = "Good evening, " + username + "!";
  } else {
    greet = "Welcome back, " + username + "!";
  }
  var el = document.getElementById("greeting-text");
  if (el) {
    el.textContent = "";
    // type greeting letter by letter....
    var i = 0;
    var timer = setInterval(function() {
      if (i < greet.length) {
        el.textContent += greet[i];
        i++;
      } else {
        clearInterval(timer);
      }
    }, 45);
  }
}

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
  closeSidebar();
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
    showResults();
    openSidebar();

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
      clickable: false,
    },
    {
      label: "Vulnerabilities Found",
      value: cveVal,
      suffix: "",
      color: cveVal > 10 ? "score-bad" : (cveVal > 3 ? "score-warn" : "score-good"),
      subtext: "View Vulnerabilities Panel ➔",
      clickable: true,
      onClick: "openSidebar()",
    },
    {
      label: "Security Headers",
      value: headerVal,
      suffix: headerVal !== "N/A" ? "%" : "",
      color: scoreColor(headerVal),
      clickable: false,
    },
  ];

  // loop scorecard array to render each box....
  for (var i = 0; i < cards.length; i++) {
    var card = cards[i];
    var el = document.createElement("div");
    el.className = "score-card" + (card.clickable ? " clickable" : "");
    if (card.clickable) {
      el.setAttribute("onclick", card.onClick);
      el.setAttribute("title", "Click to open vulnerabilities sidebar");
    }
    var subtextHtml = card.subtext ? '<div class="score-card-subtext">' + card.subtext + '</div>' : '';
    el.innerHTML = '<div class="score-value ' + card.color + '">' + card.value + card.suffix + '</div>' +
                   '<div class="score-label">' + card.label + '</div>' +
                   subtextHtml;
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
    var countEl = document.getElementById("vuln-sidebar-count");
    if (countEl) countEl.textContent = "0";
    return;
  }

  var cves = [];
  if (vuln.cves) {
    cves = vuln.cves;
  }

  var countEl = document.getElementById("vuln-sidebar-count");
  if (countEl) {
    countEl.textContent = cves.length;
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

  // Update pinned severity summary in sticky sidebar header
  var sidebarSevEl = document.getElementById("sidebar-severity-summary");
  if (sidebarSevEl) {
    sidebarSevEl.innerHTML = 
      '<div class="sidebar-sev-pill sev-CRITICAL"><span class="count">' + counts.CRITICAL + '</span><span class="label">Crit</span></div>' +
      '<div class="sidebar-sev-pill sev-HIGH"><span class="count">' + counts.HIGH + '</span><span class="label">High</span></div>' +
      '<div class="sidebar-sev-pill sev-MEDIUM"><span class="count">' + counts.MEDIUM + '</span><span class="label">Med</span></div>' +
      '<div class="sidebar-sev-pill sev-LOW"><span class="count">' + counts.LOW + '</span><span class="label">Low</span></div>';
  }

  // Update main page vulnerability summary banner
  var mainBannerEl = document.getElementById("main-vuln-banner");
  var mainBannerTitle = document.getElementById("main-vuln-title");
  var mainBannerSub = document.getElementById("main-vuln-sub");
  var mainBannerCount = document.getElementById("main-vuln-count-btn");

  if (mainBannerEl) {
    mainBannerEl.classList.remove("hidden");
    if (mainBannerTitle) {
      mainBannerTitle.textContent = cves.length + " Vulnerabilities Detected";
    }
    if (mainBannerSub) {
      mainBannerSub.textContent = counts.CRITICAL + " Critical, " + counts.HIGH + " High, " + counts.MEDIUM + " Medium, " + counts.LOW + " Low vulnerabilities found across tech stack.";
    }
    if (mainBannerCount) {
      mainBannerCount.textContent = cves.length;
    }
  }

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
        '<div class="cve-card sev-' + cve.severity + '" onclick="toggleCveCard(this, event)">' +
          '<div class="cve-header">' +
            '<span class="cve-id"><a href="' + cve.nvd_url + '" target="_blank">' + cve.cve_id + '</a></span>' +
            '<span class="sev-badge sev-' + cve.severity + '">' + cve.severity + '</span>' +
            '<span class="cvss-score">CVSS ' + cve.cvss_score + '</span>' +
            '<span class="cve-tech-tag">' + escapeHtml(cve.tech) + '</span>' +
            techVersionHtml +
            '<span class="cve-expand-indicator"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="6 9 12 15 18 9"></polyline></svg></span>' +
          '</div>' +
          '<div class="cve-desc">' + escapeHtml(cve.description) + '</div>' +
          '<div class="cve-enrichment">' +
            '<div class="enrich-section"><strong>Root Cause:</strong> ' + escapeHtml(cve.cause || "N/A") + '</div>' +
            '<div class="enrich-section"><strong>Attacker Action:</strong> ' + escapeHtml(cve.attacker_action || "N/A") + '</div>' +
            '<div class="enrich-section"><strong>Recommended Solution:</strong> ' + escapeHtml(cve.solution || "N/A") + '</div>' +
          '</div>' +
          cwesHtml +
        '</div>';
    }
  } else {
    cvesHtml = "<div class='empty-state'><p>No CVEs found for detected technologies.</p></div>";
  }

  var errorHtml = "";
  if (vuln.errors && vuln.errors.length > 0) {
    errorHtml += '<div class="card error-border">';
    errorHtml += '<div class="card-title text-danger">Lookup Errors</div>';
    // loop errors to print lists....
    for (var e = 0; e < vuln.errors.length; e++) {
      errorHtml += '<div class="error-item">' + escapeHtml(vuln.errors[e]) + '</div>';
    }
    errorHtml += '</div>';
  }

  container.innerHTML = 
    '<div class="cve-list">' + cvesHtml + '</div>' +
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
  // loop headers to build 3 col table rows....
  for (var j = 0; j < headers.length; j++) {
    var h = headers[j];
    var val = h.status === "PASS" ? escapeHtml(h.value || "") : "Not Set";
    var badgeClass = h.status === "PASS" ? "badge-pass" : "badge-fail";
    var tipText = TOOLTIPS[h.header] || "";
    var nameCell = tipText
      ? '<span class="has-tip" onmouseenter="showTooltip(event, \'' + tipText.replace(/'/g, "\\'") + '\')" onmouseleave="hideTooltip()">' + escapeHtml(h.header) + ' <span class="tip-icon">?</span></span>'
      : escapeHtml(h.header);
    headerRowsHtml +=
      '<tr class="report-row">' +
        '<td class="header-name-cell">' + nameCell + '</td>' +
        '<td class="header-value-cell">' + val + '</td>' +
        '<td class="header-status-cell"><span class="report-badge ' + badgeClass + '">' + h.status + '</span></td>' +
      '</tr>';
  }
  var headerCardHtml =
    '<div class="report-card">' +
      '<div class="report-card-header">' +
        '<div class="report-card-title has-tip" onmouseenter="showTooltip(event, \'' + TOOLTIPS["Security Headers"] + '\')" onmouseleave="hideTooltip()">Security Headers <span class="tip-icon">?</span></div>' +
        '<div class="report-card-meta">' + passCount + " / " + headers.length + " Passed</div>" +
        '<div class="report-card-bar-wrap">' +
          '<div class="report-card-bar"><div class="report-bar-fill" style="width:' + headerScore + '%;background:' + scoreHex(headerScore) + '"></div></div>' +
          '<span class="report-card-pct" style="color:' + scoreHex(headerScore) + '">' + headerScore + '%</span>' +
        '</div>' +
      '</div>' +
      '<table class="report-table">' +
        '<thead><tr><th style="width:35%">Header</th><th style="width:45%">Value</th><th style="width:20%">Status</th></tr></thead>' +
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
    rowsHtml = '<tr><td colspan="4" class="report-clear">No ' + title + ' violations found</td></tr>';
  }
  var tipText = TOOLTIPS[title] || "";
  var titleHover = tipText ? ' onmouseenter="showTooltip(event, ' + "'" + tipText + "'" + ')" onmouseleave="hideTooltip()" class="report-card-title has-tip"' : ' class="report-card-title"';
  return (
    '<div class="report-card">' +
      '<div class="report-card-header">' +
        '<div' + titleHover + '>' + title + (tipText ? ' <span class="tip-icon">?</span>' : '') + '</div>' +
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
  var idTip = TOOLTIPS[id] || "";
  var idCell = idTip
    ? '<span class="ctrl-id has-tip" onmouseenter="showTooltip(event, \'' + idTip.replace(/'/g, "\\'") + '\')" onmouseleave="hideTooltip()">' + escapeHtml(id) + ' <span class="tip-icon">?</span></span>'
    : '<span class="ctrl-id">' + escapeHtml(id) + '</span>';
  return (
    '<tr class="report-row">' +
      '<td>' + idCell + '</td>' +
      '<td>' + escapeHtml(desc) + '</td>' +
      '<td class="report-trigger">' + escapeHtml(trigger) + '</td>' +
      '<td><span class="report-badge ' + badgeClass + '">' + status + '</span></td>' +
    '</tr>'
  );
}

// build a score block in summary row with tooltip....
function makeScoreBlock(label, score) {
  var tipText = TOOLTIPS[label] || "";
  var hoverAttr = tipText ? ' onmouseenter="showTooltip(event, \'' + tipText + '\')" onmouseleave="hideTooltip()" style="cursor:default"' : '';
  return (
    '<div class="report-score-block"' + hoverAttr + '>' +
      '<div class="report-score-val" style="color:' + scoreHex(score) + '">' + score + '%</div>' +
      '<div class="report-score-label">' + label + (tipText ? ' <span class="tip-icon">?</span>' : '') + '</div>' +
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

  var tabEl = document.getElementById("tab-" + name);
  if (tabEl) tabEl.classList.add("active");
  var panelEl = document.getElementById("panel-" + name);
  if (panelEl) panelEl.classList.add("active");
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
  var banner = document.getElementById("main-vuln-banner");
  if (banner) banner.classList.add("hidden");
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

// generate and download compliance report as text file....
function downloadReport() {
  if (!currentData || !currentData.stages || !currentData.stages.compliance) {
    alert("No compliance data to download.");
    return;
  }
  var c = currentData.stages.compliance.data;
  var target = currentData.target || "Unknown Target";
  var now = new Date().toLocaleString();
  var lines = [];

  lines.push("BRON Compliance Report");
  lines.push("Target: " + target);
  lines.push("Generated: " + now);
  lines.push("");
  lines.push("--- SCORES ---");
  var s = c.scores || {};
  lines.push("Overall:          " + (s.overall || "N/A") + "%");
  lines.push("NIST 800-53:      " + (s.nist_compliance || "N/A") + "%");
  lines.push("CIS Controls:     " + (s.cis_compliance || "N/A") + "%");
  lines.push("OWASP Top 10:     " + (s.owasp_compliance || "N/A") + "%");
  lines.push("Security Headers: " + (s.security_headers || "N/A") + "%");
  lines.push("");

  lines.push("--- VULNERABILITIES DETECTED ---");
  var vulnData = null;
  if (currentData.stages.vulnerability && currentData.stages.vulnerability.data) {
    vulnData = currentData.stages.vulnerability.data;
  }
  var cves = vulnData ? (vulnData.cves || []) : [];
  if (cves.length === 0) {
    lines.push("  None");
  } else {
    for (var v = 0; v < cves.length; v++) {
      var cve = cves[v];
      lines.push("  [" + cve.cve_id + "] " + cve.severity + " (CVSS " + cve.cvss_score + ")");
      lines.push("    Technology:       " + cve.tech + (cve.tech_version ? " v" + cve.tech_version : ""));
      lines.push("    Description:      " + cve.description);
      lines.push("    Root Cause:       " + (cve.cause || "N/A"));
      lines.push("    Attacker Action:  " + (cve.attacker_action || "N/A"));
      lines.push("    Recommendation:   " + (cve.solution || "N/A"));
      if (cve.cwes && cve.cwes.length > 0) {
        lines.push("    Weaknesses:       " + cve.cwes.join(", "));
      }
      lines.push("");
    }
  }
  lines.push("");

  lines.push("--- NIST SP 800-53 CONTROLS TRIGGERED ---");
  var nist = c.nist_800_53 || [];
  if (nist.length === 0) {
    lines.push("  None");
  } else {
    for (var i = 0; i < nist.length; i++) {
      lines.push("  [" + nist[i].control + "] " + nist[i].description);
      lines.push("    Triggered by: " + nist[i].triggered_by.join(", "));
    }
  }
  lines.push("");

  lines.push("--- CIS CONTROLS TRIGGERED ---");
  var cis = c.cis_controls || [];
  if (cis.length === 0) {
    lines.push("  None");
  } else {
    for (var j = 0; j < cis.length; j++) {
      lines.push("  [" + cis[j].control + "] " + cis[j].description);
      lines.push("    Triggered by: " + cis[j].triggered_by.join(", "));
    }
  }
  lines.push("");

  lines.push("--- OWASP TOP 10 TRIGGERED ---");
  var owasp = c.owasp_top10 || [];
  if (owasp.length === 0) {
    lines.push("  None");
  } else {
    for (var k = 0; k < owasp.length; k++) {
      lines.push("  [" + owasp[k].id + "] " + owasp[k].name);
      lines.push("    Via CWEs: " + owasp[k].triggered_by_cwes.join(", "));
    }
  }
  lines.push("");

  lines.push("--- SECURITY HEADERS ---");
  var hdrs = c.security_headers || [];
  for (var h = 0; h < hdrs.length; h++) {
    lines.push("  [" + hdrs[h].status + "] " + hdrs[h].header + (hdrs[h].value ? " = " + hdrs[h].value : ""));
  }

  var blob = new Blob([lines.join("\n")], { type: "text/plain" });
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url;
  a.download = "bron_compliance_report.txt";
  a.click();
  URL.revokeObjectURL(url);
}

var TOOLTIPS = {
  "NIST SP 800-53": "NIST SP 800-53 is a catalog of security controls published by the National Institute of Standards and Technology. It is the standard for US federal systems and widely used worldwide.",
  "CIS Controls": "CIS Controls are a prioritized set of best practices from the Center for Internet Security. They help organizations defend against the most common cyber attacks.",
  "OWASP Top 10": "The OWASP Top 10 is a list of the 10 most critical web application security risks published by the Open Web Application Security Project.",
  "Security Headers": "Security Headers are HTTP response headers that instruct browsers on how to behave. Missing headers can expose users to attacks like XSS, clickjacking, and data injection.",
  "Strict-Transport-Security": "Forces browsers to use HTTPS. Prevents downgrade attacks and cookie hijacking over HTTP.",
  "Content-Security-Policy": "Defines which content sources are allowed on the page. Prevents cross-site scripting (XSS) and data injection attacks.",
  "X-Content-Type-Options": "Stops browsers from guessing the MIME type of a file. Prevents MIME sniffing attacks that can allow scripts to run unexpectedly.",
  "X-Frame-Options": "Controls whether the page can be embedded in an iframe. Prevents clickjacking attacks.",
  "X-XSS-Protection": "Enables the browser's built-in XSS filter. Blocks pages when a reflected cross-site scripting attack is detected.",
  "Referrer-Policy": "Controls how much referrer information is included with requests. Protects user privacy and prevents info leakage.",
  "Permissions-Policy": "Restricts which browser features and APIs can be used on the page. Limits exposure from compromised third-party scripts.",
  "A01:2021": "OWASP A01 — Broken Access Control: Users can act outside their intended permissions. Includes unauthorized access to accounts, files, or functions.",
  "A02:2021": "OWASP A02 — Cryptographic Failures: Weak or missing encryption exposes sensitive data in transit or at rest.",
  "A03:2021": "OWASP A03 — Injection: Untrusted data is sent to an interpreter as part of a command or query. Includes SQL injection, XSS, and command injection.",
  "A04:2021": "OWASP A04 — Insecure Design: Missing or ineffective security controls at the architecture or design level.",
  "A05:2021": "OWASP A05 — Security Misconfiguration: Improper setup of servers, frameworks, or cloud services.",
  "A06:2021": "OWASP A06 — Vulnerable and Outdated Components: Using libraries or frameworks with known vulnerabilities.",
  "A07:2021": "OWASP A07 — Identification and Authentication Failures: Weak login, session management, or credential exposure.",
  "A08:2021": "OWASP A08 — Software and Data Integrity Failures: Untrusted data or plugins are used without verification.",
  "A09:2021": "OWASP A09 — Security Logging and Monitoring Failures: Insufficient logging prevents detection and response to attacks.",
  "A10:2021": "OWASP A10 — Server-Side Request Forgery: The server fetches a URL supplied by the user, allowing attackers to reach internal systems."
};

// show tooltip near hovered element....
function showTooltip(event, text) {
  var tip = document.getElementById("bron-tooltip");
  tip.textContent = text;
  tip.classList.remove("hidden");
  positionTooltip(event);
}

// position tooltip near mouse cursor....
function positionTooltip(event) {
  var tip = document.getElementById("bron-tooltip");
  var x = event.clientX + 14;
  var y = event.clientY + 14;
  if (x + 260 > window.innerWidth) {
    x = event.clientX - 270;
  }
  tip.style.left = x + "px";
  tip.style.top = y + "px";
}

// hide tooltip on mouse leave....
function hideTooltip() {
  document.getElementById("bron-tooltip").classList.add("hidden");
}

document.addEventListener("mousemove", function(e) {
  var tip = document.getElementById("bron-tooltip");
  if (tip && !tip.classList.contains("hidden")) {
    positionTooltip(e);
  }
});

// Sidebar & Collapsible Cards management helpers
function updateOverlayState(isOpen) {
  var overlay = document.getElementById("sidebar-overlay");
  if (overlay) {
    if (isOpen) {
      overlay.classList.add("active");
    } else {
      overlay.classList.remove("active");
    }
  }
}

function toggleSidebar() {
  var sidebar = document.getElementById("vuln-sidebar");
  if (sidebar) {
    var isOpen = sidebar.classList.toggle("open");
    updateOverlayState(isOpen);
  }
}

function openSidebar() {
  var sidebar = document.getElementById("vuln-sidebar");
  if (sidebar && !sidebar.classList.contains("open")) {
    sidebar.classList.add("open");
    updateOverlayState(true);
  }
}

function closeSidebar() {
  var sidebar = document.getElementById("vuln-sidebar");
  if (sidebar && sidebar.classList.contains("open")) {
    sidebar.classList.remove("open");
    updateOverlayState(false);
  }
}

// Close vulnerabilities sidebar when clicking anywhere outside of it
document.addEventListener("click", function(e) {
  var sidebar = document.getElementById("vuln-sidebar");
  if (!sidebar || !sidebar.classList.contains("open")) return;
  if (sidebar.contains(e.target)) return;
  closeSidebar();
});

function toggleCveCard(element, event) {
  if (event && (event.target.tagName === 'A' || event.target.closest('a'))) {
    return;
  }
  element.classList.toggle("expanded");
}
