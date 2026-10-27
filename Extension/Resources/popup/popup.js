"use strict";

const api = typeof browser !== "undefined" ? browser : chrome;

const $ = (id) => document.getElementById(id);

function setEmpty(text) {
  const el = $("empty");
  el.textContent = text;
  el.hidden = false;
}

async function render() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  let host = "";
  try {
    host = new URL(tab.url).hostname;
  } catch (_) {
    // about:blank, start page, etc.
  }
  $("site").textContent = host || "No website";

  const report = await api.runtime.sendMessage({ type: "getTabReport", tabId: tab.id });
  if (!report) {
    $("trackerCount").textContent = "0";
    $("paramCount").textContent = "0";
    setEmpty(host ? "Nothing reported yet. Reload the page." : "Open a website to see activity.");
  } else {
    $("trackerCount").textContent = String(report.trackers.length);
    $("paramCount").textContent = String(report.sanitized);

    const list = $("hostList");
    for (const name of report.trackers) {
      const li = document.createElement("li");
      li.textContent = name; // textContent: hostnames come from the page
      list.appendChild(li);
    }
    if (!report.trackers.length) {
      setEmpty(report.native ? "No known trackers on this page." : "Native engine unavailable; open the Secure WebKit app once.");
    }
  }

  const stats = await api.runtime.sendMessage({ type: "getStats" });
  if (stats && stats.ok) {
    $("lifetime").textContent = `All time: ${stats.trackersDetected} trackers found, ${stats.paramsRemoved} tracking params removed.`;
  }
}

render().catch(() => setEmpty("Unable to read this page."));
