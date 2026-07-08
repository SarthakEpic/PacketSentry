let dashboardData = {
  capture: {
    file: "test_dpi.pcap",
    mode: "offline PCAP analysis",
    generatedAt: "2026-07-05",
    ciStatus: "verified",
    version: "PacketDPI 1.0"
  },
  summary: {
    packetsRead: 77,
    packetsParsed: 77,
    parseErrors: 0,
    ipv4Packets: 77,
    tcpPackets: 73,
    udpPackets: 4,
    payloadPackets: 22,
    totalBytes: 5738,
    tlsSniHits: 16,
    httpHostHits: 2,
    dnsQueryHits: 4,
    forwarded: 72,
    dropped: 5,
    flows: 43
  },
  applications: [
    { name: "HTTPS", count: 39, color: "#7dd3fc" },
    { name: "Unknown", count: 16, color: "#94a3b8" },
    { name: "DNS", count: 4, color: "#38d9a9" },
    { name: "Twitter/X", count: 1, color: "#8ab4ff" },
    { name: "HTTP", count: 2, color: "#f4c35b" },
    { name: "Google", count: 1, color: "#36c5ad" },
    { name: "Facebook", count: 1, color: "#5a8dee" },
    { name: "YouTube", count: 1, color: "#ff6b6b" },
    { name: "Instagram", count: 1, color: "#e879f9" },
    { name: "Netflix", count: 1, color: "#ef4444" },
    { name: "Amazon", count: 1, color: "#f59e0b" },
    { name: "Microsoft", count: 1, color: "#22d3ee" },
    { name: "Apple", count: 1, color: "#d1d5db" },
    { name: "Telegram", count: 1, color: "#60a5fa" },
    { name: "TikTok", count: 1, color: "#fb7185" },
    { name: "Spotify", count: 1, color: "#22c55e" },
    { name: "Zoom", count: 1, color: "#3b82f6" },
    { name: "Discord", count: 1, color: "#818cf8" },
    { name: "GitHub", count: 1, color: "#cbd5e1" },
    { name: "Cloudflare", count: 1, color: "#f97316" }
  ],
  domains: [
    { domain: "www.google.com", app: "Google", source: "TLS SNI", packets: 2, action: "Dropped", rule: "exact domain" },
    { domain: "www.youtube.com", app: "YouTube", source: "TLS SNI", packets: 2, action: "Dropped", rule: "*.youtube.com" },
    { domain: "www.facebook.com", app: "Facebook", source: "TLS SNI", packets: 2, action: "Forwarded", rule: "none" },
    { domain: "api.twitter.com", app: "Twitter/X", source: "DNS query", packets: 1, action: "Forwarded", rule: "none" },
    { domain: "twitter.com", app: "Twitter/X", source: "TLS SNI", packets: 1, action: "Forwarded", rule: "none" },
    { domain: "www.netflix.com", app: "Netflix", source: "TLS SNI", packets: 1, action: "Forwarded", rule: "none" },
    { domain: "www.microsoft.com", app: "Microsoft", source: "TLS SNI", packets: 1, action: "Forwarded", rule: "none" },
    { domain: "t.co", app: "Twitter/X", source: "TLS SNI", packets: 1, action: "Forwarded", rule: "none" },
    { domain: "github.com", app: "GitHub", source: "TLS SNI", packets: 1, action: "Forwarded", rule: "none" },
    { domain: "discord.com", app: "Discord", source: "TLS SNI", packets: 1, action: "Forwarded", rule: "none" },
    { domain: "open.spotify.com", app: "Spotify", source: "TLS SNI", packets: 1, action: "Forwarded", rule: "none" },
    { domain: "example.com", app: "HTTP", source: "HTTP Host", packets: 1, action: "Forwarded", rule: "none" },
    { domain: "www.tiktok.com", app: "TikTok", source: "TLS SNI", packets: 1, action: "Dropped", rule: "app TikTok" },
    { domain: "cloudflare.com", app: "Cloudflare", source: "DNS query", packets: 1, action: "Forwarded", rule: "none" }
  ],
  rules: [
    { type: "App", value: "TikTok", matches: 1, status: "active" },
    { type: "Domain", value: "www.google.com", matches: 2, status: "active" },
    { type: "Wildcard", value: "*.youtube.com", matches: 2, status: "active" },
    { type: "Port", value: "8080", matches: 0, status: "active" }
  ],
  timeline: [
    { label: "00:00", https: 8, dns: 0, dropped: 1, unknown: 2 },
    { label: "00:03", https: 6, dns: 1, dropped: 0, unknown: 3 },
    { label: "00:06", https: 7, dns: 0, dropped: 2, unknown: 2 },
    { label: "00:09", https: 5, dns: 1, dropped: 0, unknown: 3 },
    { label: "00:12", https: 4, dns: 1, dropped: 1, unknown: 2 },
    { label: "00:15", https: 6, dns: 0, dropped: 0, unknown: 2 },
    { label: "00:18", https: 3, dns: 1, dropped: 1, unknown: 2 }
  ],
  commands: [
    {
      label: "Analyze sample capture",
      command: ".\\build\\Debug\\packetdpi.exe analyze test_dpi.pcap"
    },
    {
      label: "Filter with demo rules",
      command: ".\\build\\Debug\\packetdpi.exe filter test_dpi.pcap demo\\filtered.pcap --rules demo\\rules.txt"
    },
    {
      label: "Benchmark parser",
      command: ".\\build\\Debug\\packetdpi.exe benchmark test_dpi.pcap --iterations 20"
    }
  ]
};

const state = {
  selectedDomain: dashboardData.domains[0],
  selectedApp: null,
  search: ""
};

const formatNumber = new Intl.NumberFormat("en-US");

function qs(selector) {
  return document.querySelector(selector);
}

function qsa(selector) {
  return [...document.querySelectorAll(selector)];
}

function showToast(message) {
  const toast = qs("#toast");
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    toast.classList.remove("visible");
  }, 1800);
}

function normalizeDashboardData(data) {
  const fallback = dashboardData;
  const normalized = {
    capture: data.capture || fallback.capture,
    summary: { ...fallback.summary, ...(data.summary || {}) },
    applications: Array.isArray(data.applications) ? data.applications : [],
    domains: Array.isArray(data.domains) ? data.domains : [],
    rules: Array.isArray(data.rules) ? data.rules : [],
    timeline: Array.isArray(data.timeline) ? data.timeline : [],
    commands: Array.isArray(data.commands) ? data.commands : fallback.commands
  };

  normalized.applications = normalized.applications.map((app) => ({
    name: app.name || "Unknown",
    count: Number(app.count || 0),
    color: app.color || "#94a3b8"
  }));

  normalized.domains = normalized.domains.map((domain) => ({
    domain: domain.domain || "(unknown)",
    app: domain.app || "Unknown",
    source: domain.source || "unknown",
    packets: Number(domain.packets || 0),
    action: domain.action || "Forwarded",
    rule: domain.rule || "none"
  }));

  normalized.timeline = normalized.timeline.map((bin) => ({
    label: bin.label || "",
    https: Number(bin.https || 0),
    dns: Number(bin.dns || 0),
    dropped: Number(bin.dropped || 0),
    unknown: Number(bin.unknown || 0)
  }));

  return normalized;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast("Copied to clipboard");
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
    showToast("Copied to clipboard");
  }
}

function metric(label, value, note, accent = "") {
  return `
    <div class="metric ${accent}">
      <span>${label}</span>
      <strong>${formatNumber.format(value)}</strong>
      <small>${note}</small>
    </div>
  `;
}

function renderMetrics() {
  const { summary } = dashboardData;
  qs("#metricGrid").innerHTML = [
    metric("Packets parsed", summary.packetsParsed, `${summary.parseErrors} parse errors`, "accent-teal"),
    metric("TLS SNI hits", summary.tlsSniHits, "domains visible before encryption", "accent-teal"),
    metric("DNS query hits", summary.dnsQueryHits, "query evidence captured", "accent-amber"),
    metric("Dropped packets", summary.dropped, `${summary.forwarded} forwarded`, "accent-red"),
    metric("Active flows", summary.flows, `${summary.tcpPackets} TCP / ${summary.udpPackets} UDP`),
    metric("Total bytes", summary.totalBytes, `${summary.payloadPackets} payload packets`)
  ].join("");
}

function renderAppChart() {
  const total = dashboardData.applications.reduce((sum, app) => sum + app.count, 0);
  const max = Math.max(1, ...dashboardData.applications.map((app) => app.count));

  qs("#appChart").innerHTML = dashboardData.applications
    .map((app) => {
      const width = Math.max(5, Math.round((app.count / max) * 100));
      const pct = total ? ((app.count / total) * 100).toFixed(1) : "0.0";
      const selected = state.selectedApp === app.name ? "selected" : "";
      return `
        <button class="app-bar ${selected}" type="button" data-app="${app.name}">
          <span class="app-name">${app.name}</span>
          <span class="bar-track">
            <span class="bar-fill" style="--value:${width}%; --bar-color:${app.color}"></span>
          </span>
          <span class="bar-count">${app.count} / ${pct}%</span>
        </button>
      `;
    })
    .join("");

  if (!dashboardData.applications.length) {
    qs("#appChart").innerHTML = `<p class="note">No application data in the loaded JSON.</p>`;
  }

  qsa(".app-bar").forEach((bar) => {
    bar.addEventListener("click", () => {
      state.selectedApp = bar.dataset.app;
      state.search = "";
      qs("#domainSearch").value = "";
      const match = dashboardData.domains.find((domain) => domain.app === state.selectedApp);
      if (match) state.selectedDomain = match;
      renderAll();
      document.getElementById("domains").scrollIntoView({ block: "start" });
    });
  });
}

function filteredDomains() {
  const search = state.search.trim().toLowerCase();
  return dashboardData.domains.filter((item) => {
    const matchesApp = !state.selectedApp || item.app === state.selectedApp;
    const haystack = `${item.domain} ${item.app} ${item.source} ${item.action}`.toLowerCase();
    return matchesApp && (!search || haystack.includes(search));
  });
}

function renderDomains() {
  const rows = filteredDomains();
  qs("#domainRows").innerHTML = rows
    .map((item) => {
      const selected = item.domain === state.selectedDomain.domain ? "selected" : "";
      const actionClass = item.action === "Dropped" ? "drop" : "forward";
      return `
        <tr class="${selected}" data-domain="${item.domain}">
          <td><strong>${item.domain}</strong></td>
          <td>${item.app}</td>
          <td>${item.source}</td>
          <td>${item.packets}</td>
          <td><span class="pill ${actionClass}">${item.action}</span></td>
        </tr>
      `;
    })
    .join("");

  if (!rows.length) {
    qs("#domainRows").innerHTML = `
      <tr>
        <td colspan="5">No matching domains for the current filter.</td>
      </tr>
    `;
  }

  qsa("#domainRows tr[data-domain]").forEach((row) => {
    row.addEventListener("click", () => {
      const domain = dashboardData.domains.find((item) => item.domain === row.dataset.domain);
      if (domain) {
        state.selectedDomain = domain;
        renderAll();
      }
    });
  });
}

function renderInspector() {
  const item = state.selectedDomain;
  if (!item) {
    qs("#inspectorBody").innerHTML = `<p class="note">No domain evidence is available in the current dashboard data.</p>`;
    return;
  }
  const command = (dashboardData.commands[1] || dashboardData.commands[0] || { command: "packetdpi analyze <capture.pcap>" }).command;
  const ruleText = item.rule === "none" ? "No matching block rule" : item.rule;
  qs("#inspectorBody").innerHTML = `
    <h3>${item.domain}</h3>
    <p class="note">PacketDPI classified this flow from ${item.source}. The action shown here comes from the demo rule set.</p>
    <div class="inspect-stat">
      <div class="inspect-row">
        <span>Application</span>
        <strong>${item.app}</strong>
      </div>
      <div class="inspect-row">
        <span>Action</span>
        <strong>${item.action}</strong>
      </div>
      <div class="inspect-row">
        <span>Matched rule</span>
        <strong>${ruleText}</strong>
      </div>
      <div class="inspect-row">
        <span>Packets</span>
        <strong>${item.packets}</strong>
      </div>
    </div>
    <p class="note">CLI source of truth:</p>
    <div class="code-line">${command}</div>
  `;
}

function renderRules() {
  const { forwarded, dropped } = dashboardData.summary;
  const total = forwarded + dropped;
  const dropDeg = total ? Math.round((dropped / total) * 360) : 0;
  qs("#dropRing").innerHTML = `
    <div class="ring-figure" style="--drop-deg:${dropDeg}deg">
      <div class="ring-inner">
        <div>
          <strong>${dropped}</strong>
          <span>dropped</span>
        </div>
      </div>
    </div>
  `;

  qs("#ruleList").innerHTML = dashboardData.rules
    .map((rule) => `
      <div class="rule-item">
        <div>
          <span>${rule.type}</span>
          <strong>${rule.value}</strong>
        </div>
        <div class="rule-count">${rule.matches}</div>
      </div>
    `)
    .join("");

  if (!dashboardData.rules.length) {
    qs("#ruleList").innerHTML = `<p class="note">No filter rules were applied for this analysis export.</p>`;
  }
}

function renderTimeline() {
  if (!dashboardData.timeline.length) {
    qs("#timelineChart").innerHTML = `<p class="note">No timeline data in the loaded JSON.</p>`;
    return;
  }

  const max = Math.max(
    ...dashboardData.timeline.map((bin) => bin.https + bin.dns + bin.dropped + bin.unknown)
  );

  qs("#timelineChart").innerHTML = dashboardData.timeline
    .map((bin) => {
      const total = bin.https + bin.dns + bin.dropped + bin.unknown;
      const scale = total / max;
      const minHeight = 16;
      const height = Math.max(minHeight, Math.round(scale * 140));
      const seg = (kind, count) => {
        const segHeight = total ? Math.max(3, Math.round((count / total) * height)) : 0;
        return count ? `<span class="seg ${kind}" style="height:${segHeight}px" title="${kind}: ${count}"></span>` : "";
      };
      return `
        <div class="time-bin" title="${bin.label}: ${total} packets">
          <div class="stack" style="height:${height}px">
            ${seg("https", bin.https)}
            ${seg("dns", bin.dns)}
            ${seg("dropped", bin.dropped)}
            ${seg("unknown", bin.unknown)}
          </div>
          <small>${bin.label}</small>
        </div>
      `;
    })
    .join("");
}

function renderCommands() {
  qs("#commandList").innerHTML = dashboardData.commands
    .map((item, index) => `
      <div class="command-item">
        <div>
          <span>${item.label}</span>
        </div>
        <div class="code-line">${item.command}</div>
        <button class="copy-small" type="button" data-command-index="${index}">Copy command</button>
      </div>
    `)
    .join("");

  qsa("[data-command-index]").forEach((button) => {
    button.addEventListener("click", () => {
      const item = dashboardData.commands[Number(button.dataset.commandIndex)];
      copyText(item.command);
    });
  });
}

function renderCaptureChip() {
  qs("#captureChip").textContent = `${dashboardData.capture.file} / ${dashboardData.capture.ciStatus}`;
}

function renderAll() {
  if (!dashboardData.domains.includes(state.selectedDomain)) {
    state.selectedDomain = dashboardData.domains[0] || null;
  }
  renderCaptureChip();
  renderMetrics();
  renderAppChart();
  renderDomains();
  renderInspector();
  renderRules();
  renderTimeline();
  renderCommands();
}

function bindInteractions() {
  qs("#domainSearch").addEventListener("input", (event) => {
    state.search = event.target.value;
    renderDomains();
  });

  qs("#clearAppFilter").addEventListener("click", () => {
    state.selectedApp = null;
    renderAll();
  });

  qs("#copyCliButton").addEventListener("click", () => {
    copyText(dashboardData.commands.map((item) => item.command).join("\n"));
  });

  qs("#loadJsonButton").addEventListener("click", () => {
    qs("#jsonFileInput").click();
  });

  qs("#jsonFileInput").addEventListener("change", async (event) => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      dashboardData = normalizeDashboardData(JSON.parse(text));
      state.selectedDomain = dashboardData.domains[0] || null;
      state.selectedApp = null;
      state.search = "";
      qs("#domainSearch").value = "";
      renderAll();
      showToast(`Loaded ${file.name}`);
    } catch {
      showToast("Could not load JSON");
    } finally {
      event.target.value = "";
    }
  });

  qs("#exportJsonButton").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(dashboardData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "packetdpi-dashboard-data.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast("JSON export prepared");
  });

  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;
      qsa(".nav-link").forEach((link) => {
        link.classList.toggle("active", link.dataset.section === visible.target.id);
      });
    },
    { rootMargin: "-20% 0px -70% 0px", threshold: [0.1, 0.25, 0.5] }
  );

  ["overview", "applications", "domains", "rules", "timeline", "export"].forEach((id) => {
    const section = document.getElementById(id);
    if (section) observer.observe(section);
  });
}

renderAll();
bindInteractions();
