/* Live system monitor controls and polling (Phase 10). */
(function () {
  "use strict";

  var root = document.getElementById("monitor-root");
  if (!root) return;

  var canControl = root.dataset.canControl === "true";
  var statusUrl = root.dataset.statusUrl;
  var eventsUrl = root.dataset.eventsUrl;
  var startUrl = root.dataset.startUrl;
  var stopUrl = root.dataset.stopUrl;
  var clearUrl = root.dataset.clearUrl;
  var csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  var el = {
    dot: document.getElementById("mon-dot"),
    state: document.getElementById("mon-state"),
    sub: document.getElementById("mon-sub"),
    start: document.getElementById("mon-start"),
    stop: document.getElementById("mon-stop"),
    clear: document.getElementById("mon-clear"),
    processed: document.getElementById("stat-processed"),
    alerts: document.getElementById("stat-alerts"),
    errors: document.getElementById("stat-errors"),
    interval: document.getElementById("stat-interval"),
    lastPoll: document.getElementById("mon-last-poll"),
    events: document.getElementById("mon-events"),
  };

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function fmtTime(ts) {
    if (!ts) return "-";
    return String(ts).replace("T", " ").slice(0, 19);
  }

  var sevClass = {
    low: "bg-emerald-500/15 text-emerald-300",
    medium: "bg-amber-500/15 text-amber-300",
    high: "bg-orange-500/15 text-orange-300",
    critical: "bg-red-500/20 text-red-300",
  };

  function post(url) {
    return fetch(url, {
      method: "POST",
      headers: { "X-CSRFToken": csrf, "Content-Type": "application/json" },
      credentials: "same-origin",
    }).then(function (r) { return r.json(); });
  }

  function renderStatus(s) {
    el.processed.textContent = s.processed;
    el.alerts.textContent = s.alerts;
    el.errors.textContent = s.errors;
    el.interval.textContent = s.interval_seconds + "s";
    el.lastPoll.textContent = s.last_poll ? "last poll " + fmtTime(s.last_poll) : "-";
    if (s.running) {
      el.dot.className = "inline-block h-3 w-3 rounded-full bg-emerald-400 animate-pulse";
      el.state.textContent = "Running";
      el.sub.textContent = "Collecting from " + s.sources.length + " source(s).";
    } else {
      el.dot.className = "inline-block h-3 w-3 rounded-full bg-slate-600";
      el.state.textContent = "Stopped";
      el.sub.textContent = "Monitoring is not running.";
    }
    if (canControl && el.start && el.stop) {
      el.start.disabled = !!s.running;
      el.stop.disabled = !s.running;
    }
  }

  function renderEvents(items) {
    if (!items || !items.length) {
      el.events.innerHTML =
        '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-600">' +
        "No activity yet. Start monitoring to collect local logs.</td></tr>";
      return;
    }
    var rows = items.map(function (e) {
      var sev = e.severity
        ? '<span class="rounded px-2 py-0.5 ' + (sevClass[e.severity] || "") + '">' + esc(e.severity) + "</span>"
        : "-";
      var alerts = e.alerts
        ? '<span class="rounded px-2 py-0.5 bg-amber-500/15 text-amber-300">' + e.alerts + "</span>"
        : '<span class="text-slate-600">0</span>';
      return (
        '<tr class="hover:bg-slate-800/40">' +
        '<td class="px-4 py-2 text-xs text-slate-500 whitespace-nowrap">' + fmtTime(e.collected_at) + "</td>" +
        '<td class="px-4 py-2 text-xs text-slate-400">' + esc(e.source_id) + "</td>" +
        '<td class="px-4 py-2 text-xs text-slate-400">' + esc(e.event_type || "-") + "</td>" +
        '<td class="px-4 py-2 text-xs">' + sev + "</td>" +
        '<td class="px-4 py-2 text-xs text-slate-300 max-w-lg truncate">' + esc(e.summary) + "</td>" +
        '<td class="px-4 py-2 text-right text-xs">' + alerts + "</td>" +
        "</tr>"
      );
    });
    el.events.innerHTML = rows.join("");
  }

  function refresh() {
    fetch(statusUrl, { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(renderStatus)
      .catch(function () {});
    fetch(eventsUrl + "?limit=100", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (d) { renderEvents(d.items); })
      .catch(function () {});
  }

  if (canControl) {
    if (el.start) el.start.addEventListener("click", function () {
      el.start.disabled = true;
      post(startUrl).then(renderStatus).catch(function () { el.start.disabled = false; });
    });
    if (el.stop) el.stop.addEventListener("click", function () {
      el.stop.disabled = true;
      post(stopUrl).then(renderStatus).catch(function () {});
    });
    if (el.clear) el.clear.addEventListener("click", function () {
      post(clearUrl).then(refresh).catch(function () {});
    });
  }

  refresh();
  setInterval(refresh, 3000);
})();
