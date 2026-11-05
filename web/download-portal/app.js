(function () {
  "use strict";

  var checksumEl = document.querySelector("[data-checksum]");
  var copyButton = document.getElementById("copy-checksum");
  var sizeEl = document.getElementById("file-size");
  var downloadLinks = document.querySelectorAll("[data-download]");

  function formatBytes(bytes) {
    if (!bytes || Number.isNaN(Number(bytes))) return "";
    var value = Number(bytes);
    var units = ["B", "KB", "MB", "GB"];
    var index = 0;
    while (value >= 1024 && index < units.length - 1) {
      value /= 1024;
      index += 1;
    }
    return value.toFixed(index === 0 ? 0 : 1) + " " + units[index];
  }

  async function loadBuildInfo() {
    try {
      var response = await fetch("./downloads/version.json", { cache: "no-store" });
      if (!response.ok) throw new Error("build metadata unavailable");
      var info = await response.json();

      if (checksumEl && info.sha256) {
        checksumEl.textContent = info.sha256;
        checksumEl.setAttribute("title", info.sha256);
      }

      if (sizeEl) {
        var details = ["Windows 10 / 11", "64-bit"];
        if (info.size_bytes) details.push(formatBytes(info.size_bytes));
        sizeEl.textContent = details.join(" · ");
      }

      if (info.file) {
        downloadLinks.forEach(function (link) {
          link.setAttribute("href", "./downloads/" + info.file);
        });
      }
    } catch (error) {
      if (checksumEl) checksumEl.textContent = "See downloads/README.txt";
    }
  }

  async function copyChecksum() {
    if (!checksumEl || !copyButton) return;
    var value = checksumEl.textContent.trim();

    try {
      await navigator.clipboard.writeText(value);
    } catch (error) {
      var textarea = document.createElement("textarea");
      textarea.value = value;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }

    copyButton.textContent = "Copied";
    window.setTimeout(function () {
      copyButton.textContent = "Copy";
    }, 1600);
  }

  if (copyButton) {
    copyButton.addEventListener("click", copyChecksum);
  }

  if ("IntersectionObserver" in window) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12 }
    );

    document.querySelectorAll(".reveal").forEach(function (element) {
      observer.observe(element);
    });
  } else {
    document.querySelectorAll(".reveal").forEach(function (element) {
      element.classList.add("is-visible");
    });
  }

  loadBuildInfo();
})();
