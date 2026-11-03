(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };

  // Build DOM safely. Device names come from the network and must NEVER be
  // inserted as HTML, so everything below uses textContent.
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ "X-Requested-With": "homesiem" }, opts.headers || {});
    return fetch(path, opts).then(function (r) {
      if (r.status === 401) { location.href = "/login"; } // the sign-in ended
      if (!r.ok) {
        return r.text().then(function (t) { throw new Error((t || "").trim() || path + " -> " + r.status); });
      }
      return r.text().then(function (t) { return t ? JSON.parse(t) : {}; });
    });
  }

  // ----- simple hash router -----
  var views = ["dashboard", "devices", "alerts", "rules", "logs", "traffic"];
  function route() {
    var v = location.hash.replace("#", "");
    if (views.indexOf(v) === -1) v = "dashboard";
    views.forEach(function (name) {
      $("view-" + name).classList.toggle("active", name === v);
    });
    document.querySelectorAll("nav a").forEach(function (a) {
      a.classList.toggle("active", a.dataset.view === v);
    });
    if (v === "traffic") { loadTraffic(); drawChart(); }
    if (v === "rules") loadRules();
    if (v === "logs") { loadLogSources(); loadLogs(false); }
  }
  window.addEventListener("hashchange", route);
  // route() runs once at the very end of this file, after everything it uses exists

  // ----- helpers -----
  function fmtUptime(s) {
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return (h ? h + "h " : "") + (m || h ? m + "m " : "") + sec + "s";
  }
  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function fmtTime(ts) {
    var d = new Date(ts * 1000);
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " +
      pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function ago(ts, now) {
    var s = Math.max(0, now - ts);
    if (s < 10) return "just now";
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }

  // ----- access control (block / slow down devices) -----
  var accessInfo = { mode: "off", reason: "" };
  function fmtKbit(k) { return k >= 1000 ? (k / 1000).toFixed(k % 1000 ? 1 : 0) + " Mbit/s" : k + " kbit/s"; }

  function renderAccess(a) {
    accessInfo = a;
    var b = $("accessBanner");
    if (a.mode === "enforcing") {
      if (a.forwarding) {
        b.className = "banner ok";
        b.textContent = "Access control is ACTIVE. Blocks and speed limits are enforced for devices whose traffic passes through this computer." +
          (a.macMatching ? "" : " (Matching by IPv4 address only: this system refused hardware-address rules.)");
      } else {
        b.className = "banner warn";
        b.textContent = "Access control is on, but this computer is not routing traffic (ip_forward is 0). Blocking affects only devices that use this computer as their gateway. If your router is a separate box, blocks will have no effect.";
      }
    } else if (a.mode === "dry-run") {
      b.className = "banner warn";
      b.textContent = "DRY RUN: nothing on your network is changed. " + a.reason + " You can still try the buttons; the rules that would be used are shown below.";
    } else {
      b.className = "banner off";
      b.textContent = a.reason || "Access control is off.";
    }
    if (a.lastError) b.textContent += " Last error: " + a.lastError;
    $("accessScript").textContent = a.script || "";
  }
  function loadAccess() { return api("/api/access").then(renderAccess).catch(function () {}); }

  function act(path, confirmText) {
    if (confirmText && !window.confirm(confirmText)) return;
    api(path, { method: "POST" })
      .then(function () { loadDevices(); loadAccess(); })
      .catch(function (e) { window.alert(e.message); });
  }
  function option(sel, value, text) {
    var o = el("option", null, text); o.value = value; sel.appendChild(o);
  }

  function accessBox(d) {
    var box = el("div", "accessbox");
    box.appendChild(el("strong", null, "Access control"));
    var state = d.blocked
      ? "Blocked" + (d.blockedUntil ? " until " + fmtTime(d.blockedUntil) : " until you unblock it")
      : d.limitKBytes ? "Speed limited to " + fmtKbit(d.limitKBytes * 8) : "Allowed";
    box.appendChild(el("p", null, "Status: " + state));
    if (accessInfo.mode === "off") {
      box.appendChild(el("p", "muted", accessInfo.reason));
      return box;
    }
    if (d.protected) {
      box.appendChild(el("p", "muted", "Protected: " + d.protectedWhy + ". It cannot be blocked or slowed down."));
    }
    var q = "?mac=" + encodeURIComponent(d.mac);
    var name = (d.hostname || d.ip) + " (" + d.ip + ")";
    var row = el("div", "accessrow");
    if (!d.protected) {
      var dur = el("select", "inp");
      [["30", "for 30 minutes"], ["60", "for 1 hour"], ["480", "for 8 hours"], ["1440", "for 24 hours"],
       ["0", "until I unblock it"]].forEach(function (o) { option(dur, o[0], o[1]); });
      var blockBtn = el("button", "btn small danger", "Block");
      blockBtn.addEventListener("click", function () {
        act("/api/access/block" + q + "&minutes=" + dur.value,
          "Block " + name + "? It will lose its network access through this computer.");
      });
      row.appendChild(blockBtn);
      row.appendChild(dur);

      var spd = el("select", "inp");
      [["512", "512 kbit/s"], ["1000", "1 Mbit/s"], ["2000", "2 Mbit/s"], ["5000", "5 Mbit/s"],
       ["10000", "10 Mbit/s"]].forEach(function (o) { option(spd, o[0], o[1]); });
      var limBtn = el("button", "btn small", "Limit speed");
      limBtn.addEventListener("click", function () { act("/api/access/limit" + q + "&kbit=" + spd.value); });
      row.appendChild(limBtn);
      row.appendChild(spd);
    }
    if (d.blocked) {
      var ub = el("button", "btn small ghost", "Unblock");
      ub.addEventListener("click", function () { act("/api/access/unblock" + q); });
      row.appendChild(ub);
    }
    if (d.limitKBytes) {
      var rl = el("button", "btn small ghost", "Remove speed limit");
      rl.addEventListener("click", function () { act("/api/access/limit" + q + "&kbit=0"); });
      row.appendChild(rl);
    }
    box.appendChild(row);

    var lab = el("label", "muted"), cb = el("input");
    cb.type = "checkbox";
    cb.checked = !!d.trusted;
    cb.addEventListener("change", function () { act("/api/access/protect" + q + "&on=" + (cb.checked ? "1" : "0")); });
    lab.appendChild(cb);
    lab.appendChild(document.createTextNode(" Never block this device (protect it)"));
    box.appendChild(lab);
    return box;
  }
  $("releaseAll").addEventListener("click", function () {
    act("/api/access/release-all", "Remove every block and speed limit for all devices?");
  });

  // ----- devices page -----
  var expanded = {};  // MAC -> true while its port details are open
  var lastData = null;
  var RISKY = { 21: 1, 23: 1, 2323: 1, 513: 1, 514: 1, 3389: 1, 5555: 1, 5900: 1, 7547: 1, 37777: 1 };

  function renderPorts(holder, ports, now) {
    holder.textContent = "";
    if (!ports.length) {
      holder.appendChild(el("p", "muted", "No open ports found among the common ports scanned."));
      return;
    }
    var t = el("table", "grid"), thead = el("thead"), hr = el("tr");
    ["Port", "Service", "Details", "First seen", "Last seen"].forEach(function (h) {
      hr.appendChild(el("th", null, h));
    });
    thead.appendChild(hr); t.appendChild(thead);
    var tb = el("tbody");
    ports.forEach(function (p) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono" + (RISKY[p.port] ? " risk" : ""), p.port + "/" + p.proto));
      tr.appendChild(el("td", null, p.service || "-"));
      tr.appendChild(el("td", "wrap", p.banner || "-"));
      tr.appendChild(el("td", null, ago(p.firstSeen, now)));
      tr.appendChild(el("td", null, ago(p.lastSeen, now)));
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    holder.appendChild(t);
  }

  function detailRow(d, now) {
    var tr = el("tr", "detail"), td = el("td");
    td.colSpan = 9;
    var box = el("div", "detailbox"), head = el("div", "detailhead");
    box.appendChild(accessBox(d));
    head.appendChild(el("strong", null, "Open ports on " + d.ip));
    head.appendChild(el("span", "muted", d.lastPortScan ? "scanned " + ago(d.lastPortScan, now) : "never scanned"));
    var sb = el("button", "btn small", "Scan this device");
    sb.addEventListener("click", function () {
      sb.disabled = true;
      api("/api/portscan?mac=" + encodeURIComponent(d.mac), { method: "POST" })
        .catch(function () { sb.disabled = false; });
    });
    head.appendChild(sb);
    box.appendChild(head);
    var holder = el("div");
    holder.appendChild(el("p", "muted", "Loading..."));
    box.appendChild(holder);
    td.appendChild(box);
    tr.appendChild(td);
    api("/api/ports?mac=" + encodeURIComponent(d.mac))
      .then(function (r) { renderPorts(holder, r.ports, now); })
      .catch(function () { holder.textContent = "Could not load ports."; });
    return tr;
  }

  function renderDevices(data) {
    lastData = data;
    $("netInfo").textContent = data.network
      ? "Scanning " + data.network
      : "Device discovery is not running (no network found).";
    $("s-net").textContent = data.network || "not running";
    setScanning(data.scanning);
    var body = $("devBody");
    body.textContent = "";
    if (!data.devices.length) {
      var tr0 = el("tr"), td0 = el("td", "empty", "No devices yet. The first scan runs right after start-up.");
      td0.colSpan = 9; tr0.appendChild(td0); body.appendChild(tr0);
      return;
    }
    data.devices.forEach(function (d) {
      var tr = el("tr");
      var st = el("td");
      st.appendChild(el("span", "dot " + (d.online ? "on" : "off")));
      st.appendChild(document.createTextNode(d.online ? " Online" : " Offline"));
      tr.appendChild(st);
      tr.appendChild(el("td", "mono", d.ip));
      var name = el("td", null, d.hostname || "-");
      if (d.self) name.appendChild(el("span", "badge", "this device"));
      tr.appendChild(name);
      tr.appendChild(el("td", null, d.vendor || "Unknown"));
      tr.appendChild(el("td", "mono", d.mac));
      var acc = el("td");
      if (d.blocked) acc.appendChild(el("span", "badge bad", "Blocked"));
      else if (d.limitKBytes) acc.appendChild(el("span", "badge warn", "Limited " + fmtKbit(d.limitKBytes * 8)));
      else if (d.protected) acc.appendChild(el("span", "badge", "Protected"));
      var mb = el("button", "btn small ghost", "Manage");
      mb.addEventListener("click", function () {
        if (expanded[d.mac]) delete expanded[d.mac]; else expanded[d.mac] = true;
        renderDevices(lastData);
      });
      acc.appendChild(mb);
      tr.appendChild(acc);
      var pc = el("td");
      var pb = el("button", "btn small ghost", d.lastPortScan ? d.openPorts + " open" : "not scanned");
      pb.addEventListener("click", function () {
        if (expanded[d.mac]) delete expanded[d.mac]; else expanded[d.mac] = true;
        renderDevices(lastData);
      });
      pc.appendChild(pb);
      tr.appendChild(pc);
      tr.appendChild(el("td", null, ago(d.firstSeen, data.now)));
      tr.appendChild(el("td", null, ago(d.lastSeen, data.now)));
      body.appendChild(tr);
      if (expanded[d.mac]) body.appendChild(detailRow(d, data.now));
    });
  }
  function loadDevices() {
    return api("/api/devices").then(renderDevices).catch(function () {});
  }
  function setScanning(on) {
    $("scanBtn").disabled = !!on;
    if (on) $("scanStatus").textContent = "Scanning...";
  }
  $("scanBtn").addEventListener("click", function () {
    setScanning(true);
    api("/api/scan", { method: "POST" }).catch(function () {
      $("scanStatus").textContent = "Scan could not start";
      $("scanBtn").disabled = false;
    });
  });
  $("portScanBtn").addEventListener("click", function () {
    $("portScanBtn").disabled = true;
    $("portStatus").textContent = "Port scan queued...";
    api("/api/portscan?mac=all", { method: "POST" }).catch(function () {
      $("portScanBtn").disabled = false;
      $("portStatus").textContent = "Port scan could not start (busy?)";
    });
  });

  // ----- account: sign out, password, version -----
  api("/api/about").then(function (a) { $("ver").textContent = "HomeSIEM " + a.version; }).catch(function () {});
  api("/api/auth/status").then(function (a) {
    if (a.authRequired) { $("logout").classList.remove("hidden"); $("pwSection").classList.remove("hidden"); }
  }).catch(function () {});
  $("logout").addEventListener("click", function () {
    api("/api/logout", { method: "POST" }).catch(function () {}).then(function () { location.href = "/login"; });
  });
  $("pwChange").addEventListener("click", function () {
    var msg = $("pwMsg");
    if ($("pwNew").value !== $("pwNew2").value) { msg.textContent = "The two new passwords are different."; return; }
    msg.textContent = "Changing...";
    api("/api/password", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current: $("pwCur").value, new: $("pwNew").value }) })
      .then(function () {
        msg.textContent = "Password changed.";
        $("pwCur").value = ""; $("pwNew").value = ""; $("pwNew2").value = "";
      })
      .catch(function (e) { msg.textContent = e.message; });
  });

  // ----- rules page -----
  function renderRules(d) {
    // the list of risky ports comes from rules.yaml, so the red labels follow it
    RISKY = {};
    (d.riskyPorts || []).forEach(function (p) { RISKY[p] = 1; });
    $("rulesPath").textContent = d.path;
    var body = $("ruleBody");
    body.textContent = "";
    d.rules.forEach(function (r) {
      var tr = el("tr");
      var name = el("td", "rulename");
      name.appendChild(el("strong", null, r.title));
      name.appendChild(el("div", "desc", r.description));
      tr.appendChild(name);
      tr.appendChild(el("td", r.enabled ? "state-on" : "state-off", r.enabled ? "On" : "Off"));
      var sev = el("td"); sev.appendChild(el("span", "pill " + r.severity, r.severity)); tr.appendChild(sev);
      tr.appendChild(el("td", null, r.cooldownMinutes ? r.cooldownMinutes + " min" : "none"));
      tr.appendChild(el("td", null, r.notify ? "yes" : "no"));
      tr.appendChild(el("td", "params", (r.params || []).join("; ") || "-"));
      body.appendChild(tr);
    });
    $("notifyInfo").textContent = d.channels && d.channels.length
      ? "Notifications go to: " + d.channels.join(", ") + ". Only alerts of " + d.minSeverity + " severity or higher are sent, at most 30 per hour."
      : "No notification channel is set up. Add Telegram, a webhook or an email account in rules.yaml to get alerts on your phone.";
    $("demoPanel").classList.toggle("hidden", !d.demo);
  }
  function loadRules() {
    return api("/api/rules").then(renderRules).catch(function () {});
  }
  $("reloadRules").addEventListener("click", function () {
    $("rulesMsg").textContent = "Reloading...";
    api("/api/rules/reload", { method: "POST" })
      .then(function () { $("rulesMsg").textContent = "Rules reloaded."; return loadRules(); })
      .catch(function (e) { $("rulesMsg").textContent = "Reload failed, the old rules are still active: " + e.message; });
  });
  $("testNotify").addEventListener("click", function () {
    $("notifyResult").textContent = "Sending...";
    api("/api/notify/test", { method: "POST" })
      .then(function (r) {
        $("notifyResult").textContent = Object.keys(r).map(function (k) { return k + ": " + r[k]; }).join("; ");
      })
      .catch(function (e) { $("notifyResult").textContent = e.message; });
  });
  document.querySelectorAll(".demo").forEach(function (b) {
    b.addEventListener("click", function () {
      api("/api/demo/attack?kind=" + b.dataset.kind, { method: "POST" })
        .then(function () { $("rulesMsg").textContent = "Fake attack sent. Check the Alerts page."; })
        .catch(function (e) { $("rulesMsg").textContent = e.message; });
    });
  });

  // ----- alerts page -----
  function renderAlerts(data) {
    var body = $("alertBody");
    body.textContent = "";
    if (!data.alerts.length) {
      var tr = el("tr"), td = el("td", "empty", "No alerts. Everything looks normal.");
      td.colSpan = 5; tr.appendChild(td); body.appendChild(tr);
      return;
    }
    data.alerts.forEach(function (a) {
      var tr = el("tr");
      if (a.acknowledged) tr.style.opacity = "0.55";
      tr.appendChild(el("td", null, fmtTime(a.ts)));
      var sev = el("td"); sev.appendChild(el("span", "pill " + a.severity, a.severity)); tr.appendChild(sev);
      tr.appendChild(el("td", null, a.rule));
      tr.appendChild(el("td", "wrap", a.message));
      var act = el("td");
      if (!a.acknowledged) {
        var b = el("button", "btn small ghost", "Acknowledge");
        b.addEventListener("click", function () {
          api("/api/alerts/ack?id=" + a.id, { method: "POST" }).then(loadAlerts);
        });
        act.appendChild(b);
      }
      tr.appendChild(act);
      body.appendChild(tr);
    });
  }
  function loadAlerts() {
    return api("/api/alerts?limit=100").then(renderAlerts).catch(function () {});
  }
  $("ackAll").addEventListener("click", function () {
    api("/api/alerts/ack?id=all", { method: "POST" }).then(loadAlerts);
  });

  // ----- traffic page -----
  var HISTORY = 60;
  var downHist = [], upHist = [];

  function fmtBytes(n) {
    if (n < 1024) return n + " B";
    var u = ["KB", "MB", "GB", "TB"], i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(n >= 100 ? 0 : 1) + " " + u[i];
  }
  function fmtRate(n) { return fmtBytes(n) + "/s"; }

  function niceMax(v) {
    var steps = [1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864, 268435456, 1073741824];
    for (var i = 0; i < steps.length; i++) if (v <= steps[i]) return steps[i];
    return v;
  }
  function drawChart() {
    var c = $("chart"), ctx = c.getContext("2d"), w = c.width, h = c.height;
    var styles = getComputedStyle(document.body);
    var left = 78, top = 10, bottom = 20, pw = w - left - 10, ph = h - top - bottom;
    var max = niceMax(Math.max.apply(null, downHist.concat(upHist, [1])));
    ctx.clearRect(0, 0, w, h);
    ctx.font = "12px sans-serif";
    ctx.fillStyle = styles.getPropertyValue("--muted");
    ctx.strokeStyle = styles.getPropertyValue("--border");
    ctx.lineWidth = 1;
    for (var i = 0; i <= 4; i++) {
      var y = top + (ph / 4) * i;
      ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(w - 10, y); ctx.stroke();
      ctx.fillText(fmtRate(Math.round(max * (1 - i / 4))), 4, y + 4);
    }
    ctx.fillText("60 s ago", left, h - 4);
    ctx.fillText("now", w - 36, h - 4);
    function line(data, color) {
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
      data.forEach(function (v, i) {
        var x = left + (i / (HISTORY - 1)) * pw + (HISTORY - data.length) * (pw / (HISTORY - 1));
        var y = top + ph - (v / max) * ph;
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }
    line(downHist, styles.getPropertyValue("--accent"));
    line(upHist, styles.getPropertyValue("--ok"));
  }

  function onTraffic(d) {
    downHist.push(d.down); upHist.push(d.up);
    if (downHist.length > HISTORY) { downHist.shift(); upHist.shift(); }
    var txt = "\u2193 " + fmtRate(d.down) + "   \u2191 " + fmtRate(d.up);
    $("c-traffic").textContent = txt;
    $("t-now").textContent = "  Now: " + txt + "   (" + d.pps + " packets/s)";
    if (location.hash === "#traffic") drawChart();
  }

  function renderTraffic(d) {
    var b = $("tStatus");
    b.className = "banner " + (d.mode === "live" ? "ok" : d.mode === "demo" ? "warn" : "off");
    b.textContent = (d.mode === "live" ? "Live capture on " + d.iface + ". "
      : d.mode === "demo" ? "DEMO MODE: simulated traffic. " : "Capture is off. ") + d.note;
    $("t-down").textContent = fmtBytes(d.totals.down);
    $("t-up").textContent = fmtBytes(d.totals.up);
    $("t-lan").textContent = fmtBytes(d.totals.lan);
    $("t-other").textContent = fmtBytes(d.totals.other);
    $("t-packets").textContent = d.totals.packets;
    $("t-dropped").textContent = d.dropped;

    var tb = $("talkBody");
    tb.textContent = "";
    if (!d.talkers.length) {
      var r0 = el("tr"), c0 = el("td", "empty", "No traffic seen yet.");
      c0.colSpan = 6; r0.appendChild(c0); tb.appendChild(r0);
    }
    d.talkers.forEach(function (t) {
      var tr = el("tr");
      tr.appendChild(el("td", null, t.name || "-"));
      tr.appendChild(el("td", "mono", t.ip));
      tr.appendChild(el("td", "num", fmtBytes(t.sent)));
      tr.appendChild(el("td", "num", fmtBytes(t.recv)));
      tr.appendChild(el("td", "num", fmtRate(t.sentRate)));
      tr.appendChild(el("td", "num", fmtRate(t.recvRate)));
      tb.appendChild(tr);
    });

    var rb = $("remBody");
    rb.textContent = "";
    if (!d.remote.length) {
      var r1 = el("tr"), c1 = el("td", "empty", "Nothing saved yet. Flows are saved every minute.");
      c1.colSpan = 5; r1.appendChild(c1); rb.appendChild(r1);
    }
    d.remote.forEach(function (h) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", h.host));
      tr.appendChild(el("td", null, h.port ? h.port + "/" + h.proto + (h.service ? " " + h.service : "") : h.proto));
      tr.appendChild(el("td", "num", fmtBytes(h.down)));
      tr.appendChild(el("td", "num", fmtBytes(h.up)));
      tr.appendChild(el("td", "num", h.packets));
      rb.appendChild(tr);
    });
  }
  function loadTraffic() {
    return api("/api/traffic").then(renderTraffic).catch(function () {});
  }
  setInterval(function () { if (location.hash === "#traffic") loadTraffic(); }, 5000);

  // ----- collected logs page -----
  var SEV = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"];
  var oldestLogId = 0;
  var hostKey = "";

  function showTab(which) {
    $("paneCollected").classList.toggle("hidden", which !== "collected");
    $("paneEvents").classList.toggle("hidden", which !== "events");
    $("tabCollected").classList.toggle("ghost", which !== "collected");
    $("tabEvents").classList.toggle("ghost", which !== "events");
  }
  $("tabCollected").addEventListener("click", function () { showTab("collected"); loadLogs(false); });
  $("tabEvents").addEventListener("click", function () { showTab("events"); });

  function logUrl(before) {
    var p = [];
    function add(k, v) { if (v) p.push(k + "=" + encodeURIComponent(v)); }
    add("q", $("fQ").value.trim());
    add("host", $("fHost").value);
    add("level", $("fLevel").value);
    add("hours", $("fHours").value === "0" ? "" : $("fHours").value);
    if (before) add("before", String(before));
    p.push("limit=100");
    return "/api/logs?" + p.join("&");
  }

  // Log text comes from other machines, so it is only ever inserted as text.
  function renderLogRows(rows, append) {
    var body = $("logBody");
    if (!append) { body.textContent = ""; oldestLogId = 0; }
    if (!rows.length && !append) {
      var tr0 = el("tr"), td0 = el("td", "empty", "No log messages match. Send some with the instructions below, or press a test button.");
      td0.colSpan = 5; tr0.appendChild(td0); body.appendChild(tr0);
      return;
    }
    rows.forEach(function (r) {
      var tr = el("tr");
      tr.appendChild(el("td", null, fmtTime(r.ts)));
      tr.appendChild(el("td", null, r.host));
      tr.appendChild(el("td", null, r.program || "-"));
      var lv = el("td");
      lv.appendChild(el("span", "pill " + (r.severity <= 3 ? "high" : r.severity === 4 ? "medium" : ""), SEV[r.severity] || "?"));
      tr.appendChild(lv);
      tr.appendChild(el("td", "msg", r.message));
      body.appendChild(tr);
      oldestLogId = r.id; // newest first, so the last row is the oldest
    });
  }

  function loadLogs(older) {
    return api(logUrl(older ? oldestLogId : 0)).then(function (d) {
      renderLogRows(d.logs, !!older);
      $("logMore").classList.toggle("hidden", d.logs.length < 100);
    }).catch(function () {});
  }

  function buildHelp(port) {
    var h = location.hostname, p = port || "514";
    var note = (h === "127.0.0.1" || h === "localhost")
      ? "(You opened this page on the same computer, so replace " + h + " below with this computer's network address, for example 192.168.1.16.)\n\n"
      : "";
    $("logHelp").textContent = note +
      "Router or any device with a 'remote syslog' / 'log server' setting:\n" +
      "  server " + h + "    port " + p + "    protocol UDP\n\n" +
      "Linux computer (rsyslog), sends everything:\n" +
      "  echo '*.* @" + h + ":" + p + "' | sudo tee /etc/rsyslog.d/90-homesiem.conf\n" +
      "  sudo systemctl restart rsyslog\n" +
      "  (use @@ instead of @ to send over TCP)\n\n" +
      "Any computer, with the HomeSIEM agent (the same program you are running):\n" +
      "  ./homesiem-linux agent -server " + h + ":" + p + " -file /var/log/auth.log\n" +
      "  homesiem.exe agent -server " + h + ":" + p + " -file C:\\path\\to\\app.log";
  }

  function loadLogSources() {
    return api("/api/logs/sources").then(function (d) {
      var s = d.status;
      $("logStatus").textContent = s.enabled
        ? "Receiving on " + s.listening.join(" and ") + ". " + s.received + " messages received, " + d.total +
          " stored, " + s.dropped + " dropped."
        : "The log receiver is not running. The Logs tab 'HomeSIEM events' says why.";
      buildHelp(s.port);
      var key = d.sources.map(function (x) { return x.host + ":" + x.count; }).join("|");
      if (key !== hostKey) { // rebuild the list only when it changed, so an open menu is not disturbed
        hostKey = key;
        var sel = $("fHost"), cur = sel.value;
        sel.textContent = "";
        var all = el("option", null, "All machines"); all.value = ""; sel.appendChild(all);
        d.sources.forEach(function (x) {
          var o = el("option", null, x.host + " (" + x.count + ")"); o.value = x.host; sel.appendChild(o);
        });
        sel.value = cur;
      }
    }).catch(function () {});
  }

  $("fSearch").addEventListener("click", function () { loadLogs(false); });
  $("fQ").addEventListener("keydown", function (e) { if (e.key === "Enter") loadLogs(false); });
  ["fHost", "fLevel", "fHours"].forEach(function (id) {
    $(id).addEventListener("change", function () { loadLogs(false); });
  });
  $("logMore").addEventListener("click", function () { loadLogs(true); });
  document.querySelectorAll(".logtest").forEach(function (b) {
    b.addEventListener("click", function () {
      $("logTestMsg").textContent = "Sending...";
      api("/api/logs/test?kind=" + b.dataset.kind, { method: "POST" })
        .then(function () {
          $("logTestMsg").textContent = b.dataset.kind === "bruteforce"
            ? "Sent. After a moment a 'log:login_failures' alert should appear on the Alerts page."
            : "Sent. The message should appear in the table in a moment.";
          setTimeout(function () { loadLogs(false); loadLogSources(); }, 1800);
        })
        .catch(function (e) { $("logTestMsg").textContent = e.message; });
    });
  });
  setInterval(function () {
    if (location.hash === "#logs" && !$("paneCollected").classList.contains("hidden") && $("fAuto").checked) {
      loadLogSources();
      loadLogs(false);
    }
  }, 3000);

  // ----- log view (stored events) -----
  var logEl = $("log");
  var lines = [];
  var lastId = 0;
  function addLog(e) {
    if (e.id <= lastId) return;
    lastId = e.id;
    lines.push("[" + fmtTime(e.ts) + "] " + e.level.toUpperCase() + " " + e.source + ": " + e.message);
    if (lines.length > 300) lines.shift();
  }
  function renderLog() {
    var atBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 20;
    logEl.textContent = lines.join("\n");
    if (atBottom) logEl.scrollTop = logEl.scrollHeight;
  }

  // ----- live updates (Server-Sent Events, auto-reconnects) -----
  function onTick(d) {
    $("c-devices").textContent = d.online + " / " + d.devices;
    $("c-alerts").textContent = d.alerts;
    $("c-ports").textContent = d.ports;
    $("c-access").textContent = d.blocked + " / " + d.limited;
    $("c-mem").textContent = d.memMB;
    $("c-uptime").textContent = fmtUptime(d.uptimeSec);
    $("c-db").textContent = d.dbKB;
    $("s-platform").textContent = d.os + " / " + d.arch;
    $("s-cpus").textContent = d.cpus;
    $("s-gor").textContent = d.goroutines;
    $("s-clients").textContent = d.clients;
    $("s-last").textContent = d.time;
  }
  function onScan(d) {
    if (d.state === "start") { setScanning(true); return; }
    $("scanBtn").disabled = false;
    $("scanStatus").textContent = "Last scan: " + d.found + " devices in " + (d.ms / 1000).toFixed(1) + "s" +
      (d["new"] ? " (" + d["new"] + " new)" : "");
  }
  function onPortScan(d) {
    if (d.state === "start") {
      $("portScanBtn").disabled = true;
      $("portStatus").textContent = "Port scan: 0/" + d.total + " devices";
    } else if (d.state === "progress") {
      $("portStatus").textContent = "Port scan: " + d.done + "/" + d.total + " devices";
    } else {
      $("portScanBtn").disabled = false;
      $("portStatus").textContent = "Port scan finished: " + d.open + " open ports on " + d.total +
        " devices in " + (d.ms / 1000).toFixed(1) + "s";
    }
  }
  function startLive() {
    var es = new EventSource("/events");
    es.onopen = function () {
      $("dot").classList.add("on"); $("connText").textContent = "live";
    };
    es.onerror = function () {
      $("dot").classList.remove("on"); $("connText").textContent = "reconnecting...";
      api("/api/auth/status").then(function (a) { // a stream that stops may mean the sign-in ended
        if (a.authRequired && !a.authenticated) location.href = "/login";
      }).catch(function () {});
    };
    es.onmessage = function (e) {
      var d = JSON.parse(e.data);
      switch (d.type) {
        case "tick": onTick(d); break;
        case "event": addLog(d); renderLog(); break;
        case "alert": loadAlerts(); break;
        case "devices": loadDevices(); loadAccess(); break;
        case "scan": onScan(d); break;
        case "portscan": onPortScan(d); break;
        case "traffic": onTraffic(d); break;
      }
    };
  }

  // Load stored data first, then go live, so nothing is duplicated.
  route();
  loadDevices();
  loadAlerts();
  loadRules();
  loadAccess();
  setInterval(loadDevices, 30000); // keeps "5m ago" labels fresh
  api("/api/events?limit=200")
    .then(function (list) { list.reverse().forEach(addLog); renderLog(); })
    .catch(function () {})
    .then(startLive);
})();
