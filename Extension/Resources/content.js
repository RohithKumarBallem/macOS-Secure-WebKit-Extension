"use strict";

// Runs in the top frame of every http(s) page.
//  1. Removes tracking parameters from the address bar (history.replaceState).
//  2. Removes them from links at the moment they are clicked.
//  3. After load, reports the third-party hostnames the page references so the
//     native engine can say which are trackers. Only hostnames leave this file,
//     and only to the extension's own background script.

(() => {
  const api = typeof browser !== "undefined" ? browser : chrome;

  let exact = null;
  let prefixes = [];
  let sanitizedLinks = 0;
  let locationParamsRemoved = 0;

  function isTracking(name) {
    if (!exact) return false;
    const lower = name.toLowerCase();
    return exact.has(lower) || prefixes.some((prefix) => lower.startsWith(prefix));
  }

  // Works on the raw query so untouched parameters keep their exact encoding.
  function sanitizeSearch(search) {
    if (!search || search.length < 2) return null;
    const kept = [];
    let removed = 0;
    for (const segment of search.slice(1).split("&")) {
      if (!segment) continue;
      const eq = segment.indexOf("=");
      const name = eq < 0 ? segment : segment.slice(0, eq);
      if (isTracking(name)) removed++;
      else kept.push(segment);
    }
    return removed ? { search: kept.length ? "?" + kept.join("&") : "", removed } : null;
  }

  function cleanLocation() {
    const result = sanitizeSearch(location.search);
    if (!result) return;
    try {
      history.replaceState(history.state, "", location.pathname + result.search + location.hash);
      locationParamsRemoved += result.removed;
    } catch (_) {
      // Some documents (sandboxed, opaque origin) refuse replaceState.
    }
  }

  function onLinkActivated(event) {
    const target = event.target;
    const anchor = target && target.closest ? target.closest("a[href]") : null;
    if (!anchor || (anchor.protocol !== "http:" && anchor.protocol !== "https:")) return;
    const result = sanitizeSearch(anchor.search);
    if (!result) return;
    anchor.search = result.search;
    sanitizedLinks++;
  }

  function thirdPartyHosts() {
    const hosts = new Set();
    const add = (value) => {
      if (!value) return;
      try {
        const url = new URL(value, location.href);
        if ((url.protocol === "http:" || url.protocol === "https:" || url.protocol === "wss:" || url.protocol === "ws:") &&
            url.hostname && url.hostname !== location.hostname) {
          hosts.add(url.hostname);
        }
      } catch (_) {
        // Not a URL.
      }
    };
    for (const entry of performance.getEntriesByType("resource")) add(entry.name);
    // Blocked requests never produce a resource entry, but their elements remain.
    for (const el of document.querySelectorAll("script[src], img[src], iframe[src], link[href], video[src], audio[src], source[src], embed[src]")) {
      add(el.getAttribute("src") || el.getAttribute("href"));
    }
    return [...hosts].slice(0, 200);
  }

  function report() {
    api.runtime.sendMessage({
      type: "pageReport",
      firstParty: location.hostname,
      hosts: thirdPartyHosts(),
      sanitizedLinks,
      locationParamsRemoved,
    }).catch(() => {});
  }

  async function start() {
    let config;
    try {
      config = await api.runtime.sendMessage({ type: "getConfig" });
    } catch (_) {
      return;
    }
    if (!config || !Array.isArray(config.params)) return;

    exact = new Set(config.params.map((p) => String(p).toLowerCase()));
    prefixes = (config.paramPrefixes || []).map((p) => String(p).toLowerCase());

    cleanLocation();
    // Capture phase, so we run before page handlers read anchor.href.
    document.addEventListener("click", onLinkActivated, true);
    document.addEventListener("auxclick", onLinkActivated, true);
  }

  start();

  window.addEventListener("load", () => {
    // Let late-loading tags show up, and stay off the critical path.
    const run = () => setTimeout(report, 1500);
    if ("requestIdleCallback" in window) requestIdleCallback(run, { timeout: 3000 });
    else run();
  }, { once: true });
})();
