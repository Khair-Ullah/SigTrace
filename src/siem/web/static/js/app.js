/* Realtime alert notifications via SocketIO (FR-49, FR-51). */
(function () {
  "use strict";

  const indicator = document.getElementById("realtime-indicator");
  const container = document.getElementById("toast-container");

  function setIndicator(connected) {
    if (!indicator) return;
    indicator.innerHTML =
      '<span class="inline-block h-2 w-2 rounded-full ' +
      (connected ? "bg-emerald-400" : "bg-slate-600") +
      '"></span> ' + (connected ? "live" : "offline");
  }

  function toast(title, body, severity) {
    if (!container) return;
    const colors = {
      low: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
      medium: "border-amber-500/40 bg-amber-500/10 text-amber-200",
      high: "border-orange-500/40 bg-orange-500/10 text-orange-200",
      critical: "border-red-500/40 bg-red-500/10 text-red-200",
    };
    const el = document.createElement("div");
    el.className =
      "toast rounded-lg border p-3 text-sm shadow-lg " +
      (colors[severity] || "border-slate-600 bg-slate-800 text-slate-200");
    el.innerHTML =
      '<div class="font-medium">' + title + "</div>" +
      '<div class="text-xs opacity-80">' + body + "</div>";
    container.appendChild(el);
    setTimeout(function () {
      el.style.transition = "opacity .3s";
      el.style.opacity = "0";
      setTimeout(function () { el.remove(); }, 300);
    }, 8000);
  }

  if (typeof io === "undefined") return; // socket.io client not loaded
  const socket = io("/realtime", { transports: ["websocket", "polling"] });

  socket.on("connect", function () { setIndicator(true); });
  socket.on("disconnect", function () { setIndicator(false); });
    socket.on("alert", function (payload) {
    var a = payload && payload.alert;
    if (!a) return;
    toast(
      "[" + (a.severity || "").toUpperCase() + "] " + a.rule_name,
      (a.src_ip || "unknown source") +
        (payload.incident ? " • " + payload.incident.title : ""),
      a.severity
    );
    try {
      var p = window.location.pathname || "";
      if (p.indexOf("/dashboard") === 0 || p === "/" || p.indexOf("/alerts") === 0 || p.indexOf("/incidents") === 0) {
        setTimeout(function(){ window.location.reload(); }, 1500);
      }
    } catch (e) {}
  });
  socket.on("incident", function (incident) {
    if (incident) {
      toast("Incident: " + incident.title,
        (incident.severity || "") + " • " + (incident.status || ""), incident.severity);
      try {
        var p = window.location.pathname || "";
        if (p.indexOf("/dashboard") === 0 || p === "/" || p.indexOf("/incidents") === 0 || p.indexOf("/alerts") === 0) {
          setTimeout(function(){ window.location.reload(); }, 1500);
        }
      } catch (e) {}
    }
  });
})();
