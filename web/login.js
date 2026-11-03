(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };

  function post(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "X-Requested-With": "homesiem", "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) {
      if (r.ok) return;
      return r.text().then(function (t) {
        throw new Error((t || "").trim() || "Something went wrong (" + r.status + ").");
      });
    });
  }

  fetch("/api/auth/status", { headers: { "X-Requested-With": "homesiem" } })
    .then(function (r) { return r.json(); })
    .then(function (s) {
      if (s.authenticated || !s.authRequired) { location.href = "/"; return; }
      $("loading").classList.add("hidden");
      if (s.setupRequired) { $("setupForm").classList.remove("hidden"); $("code").focus(); }
      else { $("loginForm").classList.remove("hidden"); $("pw").focus(); }
    })
    .catch(function () { $("loading").textContent = "Cannot reach HomeSIEM. Is it running?"; });

  $("loginForm").addEventListener("submit", function (e) {
    e.preventDefault();
    $("loginMsg").textContent = "Checking...";
    post("/api/login", { password: $("pw").value })
      .then(function () { location.href = "/"; })
      .catch(function (err) { $("loginMsg").textContent = err.message; $("pw").value = ""; $("pw").focus(); });
  });

  $("setupForm").addEventListener("submit", function (e) {
    e.preventDefault();
    if ($("pw1").value !== $("pw2").value) { $("setupMsg").textContent = "The two passwords are different."; return; }
    $("setupMsg").textContent = "Creating...";
    post("/api/setup", { code: $("code").value, password: $("pw1").value })
      .then(function () { location.href = "/"; })
      .catch(function (err) { $("setupMsg").textContent = err.message; });
  });
})();
