"use strict";

// Blocking and parameter redirects are declarative (rules/*.json), so nothing in
// this file sits in the request path. It only relays page reports to the native
// engine and keeps per-tab results for the popup.

const api = typeof browser !== "undefined" ? browser : chrome;

// Safari routes native messages to the containing app's extension handler and
// ignores the application id, but the argument is still required.
const NATIVE_APP_ID = "application.id";

const MAX_HOSTS = 200;
const MAX_HOST_LENGTH = 253;

let configPromise = null;

function loadConfig() {
  if (!configPromise) {
    configPromise = fetch(api.runtime.getURL("rules/config.json"))
      .then((response) => response.json())
      .catch((error) => {
        configPromise = null;
        throw error;
      });
  }
  return configPromise;
}

async function callNative(message) {
  try {
    const reply = await api.runtime.sendNativeMessage(NATIVE_APP_ID, message);
    return reply && typeof reply === "object" ? reply : { ok: false, error: "empty reply" };
  } catch (error) {
    return { ok: false, error: String((error && error.message) || error) };
  }
}

function tabKey(tabId) {
  return "tab:" + tabId;
}

function cleanHosts(value) {
  if (!Array.isArray(value)) return [];
  const hosts = new Set();
  for (const item of value) {
    if (typeof item === "string" && item.length > 0 && item.length <= MAX_HOST_LENGTH) {
      hosts.add(item.toLowerCase());
      if (hosts.size >= MAX_HOSTS) break;
    }
  }
  return [...hosts];
}

function count(value) {
  return Number.isInteger(value) && value >= 0 && value <= 100000 ? value : 0;
}

async function handlePageReport(message, sender) {
  const tab = sender && sender.tab;
  if (!tab || typeof tab.id !== "number") return { ok: false };

  const firstParty = typeof message.firstParty === "string" ? message.firstParty.slice(0, MAX_HOST_LENGTH) : "";
  const hosts = cleanHosts(message.hosts);
  const sanitized = count(message.sanitizedLinks) + count(message.locationParamsRemoved);

  const verdict = hosts.length ? await callNative({ cmd: "classify", firstParty, hosts }) : { ok: true, trackers: [] };
  const trackers = verdict.ok && Array.isArray(verdict.trackers) ? verdict.trackers : [];

  await api.storage.session.set({
    [tabKey(tab.id)]: { firstParty, trackers, sanitized, native: Boolean(verdict.ok), at: Date.now() },
  });
  api.action.setBadgeText({ tabId: tab.id, text: trackers.length ? String(trackers.length) : "" }).catch(() => {});

  if (trackers.length || sanitized) {
    callNative({ cmd: "report", detected: trackers.length, sanitized });
  }
  return { ok: true };
}

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") return false;

  let work;
  switch (message.type) {
    case "getConfig":
      work = loadConfig();
      break;
    case "pageReport":
      work = handlePageReport(message, sender);
      break;
    case "getTabReport":
      work = api.storage.session
        .get(tabKey(message.tabId))
        .then((stored) => stored[tabKey(message.tabId)] || null);
      break;
    case "getStats":
      work = callNative({ cmd: "stats" });
      break;
    default:
      return false;
  }
  work.then(sendResponse, () => sendResponse(null));
  return true; // asynchronous response
});

api.tabs.onRemoved.addListener((tabId) => {
  api.storage.session.remove(tabKey(tabId)).catch(() => {});
});

api.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    api.storage.session.remove(tabKey(tabId)).catch(() => {});
    api.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  }
});
