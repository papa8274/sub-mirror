import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const WORKER_URL = String(process.env.WORKER_URL || "").replace(/\/+$/, "");
const HEALTH_SECRET = String(process.env.WORKER_HEALTH_SECRET || "");
const SING_BOX_BIN = String(process.env.SING_BOX_BIN || "sing-box");
const TCP_TIMEOUT_MS = Number(process.env.TCP_TIMEOUT_MS || 3500);
const TLS_TIMEOUT_MS = Number(process.env.TLS_TIMEOUT_MS || 4000);
const DNS_TIMEOUT_MS = Number(process.env.DNS_TIMEOUT_MS || 3000);
const PROTOCOL_TIMEOUT_MS = Number(process.env.PROTOCOL_TIMEOUT_MS || 8000);
const DNS_CONCURRENCY = Number(process.env.DNS_CONCURRENCY || 60);
const TCP_CONCURRENCY = Number(process.env.TCP_CONCURRENCY || 60);
const ENDPOINT_CONCURRENCY = Math.max(1, Number(process.env.ENDPOINT_CONCURRENCY || Math.min(DNS_CONCURRENCY, TCP_CONCURRENCY)));
const PROTOCOL_CONCURRENCY = Number(process.env.PROTOCOL_CONCURRENCY || 18);
const TCP_SAMPLES = Math.max(1, Math.min(5, Number(process.env.TCP_SAMPLES || 3)));
const LEGACY_GEO_CONCURRENCY = Number(process.env.LEGACY_GEO_CONCURRENCY || 4);
const LEGACY_GEO_MAX_PER_RUN = Math.min(45, Number(process.env.LEGACY_GEO_MAX_PER_RUN || 45));
const COUNTRY_BATCH_SIZE = 100;
const TEST_URL = String(process.env.PROTOCOL_TEST_URL || "https://cp.cloudflare.com/generate_204");

if (!WORKER_URL || !/^https:\/\//i.test(WORKER_URL)) {
  throw new Error("WORKER_URL must be a valid https:// URL");
}
if (!HEALTH_SECRET) throw new Error("WORKER_HEALTH_SECRET is missing");

const TCP_PROTOCOLS = new Set(["vless", "vmess", "trojan", "ss", "ssr", "ssh"]);
const PROTOCOL_TEST_PROTOCOLS = new Set(["vless", "vmess", "trojan", "ss", "hysteria2", "tuic"]);
const UDP_PROTOCOLS = new Set(["hysteria", "hysteria2", "tuic", "wireguard"]);
const U_TLS_FINGERPRINTS = new Set(["chrome", "firefox", "safari", "edge", "ios", "android", "random", "randomized"]);
const RESERVED_LOCAL_PORTS = new Set();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeHost(value) {
  return String(value || "").trim().replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
}

function normalizeProtocol(value) {
  const protocol = String(value || "").trim().toLowerCase();
  if (protocol === "hy2") return "hysteria2";
  if (protocol === "wg") return "wireguard";
  return protocol;
}

function decodeURIComponentSafe(value) {
  try { return decodeURIComponent(String(value || "")); }
  catch { return String(value || ""); }
}

function decodeBase64Flexible(value) {
  let text = String(value || "").trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  while (text.length % 4) text += "=";
  return Buffer.from(text, "base64").toString("utf8");
}

function stripFragment(value) {
  const text = String(value || "");
  const index = text.indexOf("#");
  return index >= 0 ? text.slice(0, index) : text;
}

function boolParam(value) {
  const text = String(value || "").trim().toLowerCase();
  return ["1", "true", "yes", "on"].includes(text);
}

function splitList(value) {
  return String(value || "")
    .split(/[;,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function isPublicIp(ip) {
  const family = net.isIP(ip);
  if (!family) return false;
  if (family === 4) {
    const p = ip.split(".").map(Number);
    const [a, b] = p;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    return true;
  }
  const v = ip.toLowerCase();
  if (v === "::" || v === "::1") return false;
  if (v.startsWith("fc") || v.startsWith("fd")) return false;
  if (/^fe[89ab]/.test(v)) return false;
  return true;
}

function median(values) {
  const sorted = values.filter((value) => Number.isFinite(value) && value > 0).sort((a, b) => a - b);
  if (!sorted.length) return 0;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}

async function withTimeout(promise, ms, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timeout`)), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function isTransientStatus(status) {
  const code = Number(status);
  return code === 408 || code === 425 || code === 429 || (code >= 500 && code <= 599);
}

function retryAfterMsFrom(error, fallbackMs) {
  const fromData = Number(error?.data?.retryAfterSeconds);
  if (Number.isFinite(fromData) && fromData > 0) return Math.max(1000, Math.min(120000, fromData * 1000));
  const header = error?.headers?.get?.("retry-after");
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds > 0) return Math.max(1000, Math.min(120000, seconds * 1000));
  return fallbackMs;
}

async function fetchJson(url, options = {}, retries = 3) {
  let lastError;
  const attempts = Math.max(1, Number(retries) || 1);

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 20000);
      let response;
      try {
        response = await fetch(url, { ...options, signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }

      const text = await response.text();
      let data = null;
      try { data = text ? JSON.parse(text) : {}; }
      catch { data = { raw: text }; }

      if (!response.ok) {
        const error = new Error(`HTTP ${response.status}: ${data?.error || text || response.statusText}`);
        error.status = response.status;
        error.data = data;
        error.headers = response.headers;
        throw error;
      }
      return { data, headers: response.headers, status: response.status };
    } catch (error) {
      lastError = error;
      const transient = !Number.isFinite(Number(error?.status)) || isTransientStatus(error?.status);
      if (!transient || attempt >= attempts) break;
      const base = Math.min(10000, 700 * (2 ** (attempt - 1)));
      const waitMs = retryAfterMsFrom(error, base + Math.floor(Math.random() * 300));
      await sleep(waitMs);
    }
  }

  throw lastError;
}
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let index = 0;
  async function worker() {
    while (true) {
      const current = index++;
      if (current >= items.length) return;
      try {
        results[current] = await fn(items[current], current);
      } catch (error) {
        results[current] = { error: error?.message || String(error) };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length || 1) }, () => worker()));
  return results;
}

async function resolveHost(host) {
  const normalized = normalizeHost(host);
  if (net.isIP(normalized)) {
    return isPublicIp(normalized)
      ? { ip: normalized, geoSource: "direct-ip", countryConfidence: "high" }
      : { ip: "", geoSource: "none", countryConfidence: "unknown" };
  }

  try {
    const rows = await withTimeout(
      dns.lookup(normalized, { all: true, verbatim: true }),
      DNS_TIMEOUT_MS,
      "DNS"
    );
    const publicRows = rows.filter((row) => isPublicIp(row.address));
    publicRows.sort((a, b) => a.family - b.family || a.address.localeCompare(b.address));
    return publicRows.length
      ? { ip: publicRows[0].address, geoSource: "dns", countryConfidence: "medium" }
      : { ip: "", geoSource: "none", countryConfidence: "unknown" };
  } catch {
    return { ip: "", geoSource: "none", countryConfidence: "unknown" };
  }
}

async function tcpProbeOnce(host, port) {
  const started = Date.now();
  return await new Promise((resolve) => {
    let settled = false;
    const socket = net.createConnection({ host, port: Number(port) });
    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(TCP_TIMEOUT_MS);
    socket.once("connect", () => finish({
      ok: true,
      latencyMs: Math.max(1, Date.now() - started),
      remoteIp: isPublicIp(normalizeHost(socket.remoteAddress || "")) ? normalizeHost(socket.remoteAddress) : "",
      error: "",
    }));
    socket.once("timeout", () => finish({ ok: false, latencyMs: 0, remoteIp: "", error: "timeout" }));
    socket.once("error", (error) => finish({
      ok: false,
      latencyMs: 0,
      remoteIp: "",
      error: String(error?.code || error?.message || "connection error").slice(0, 120),
    }));
  });
}

async function tcpProbeSamples(host, port) {
  const samples = [];
  const remoteIps = new Map();
  let lastError = "";
  for (let i = 0; i < TCP_SAMPLES; i += 1) {
    const result = await tcpProbeOnce(host, port);
    if (result.ok) {
      samples.push(result.latencyMs);
      if (result.remoteIp) remoteIps.set(result.remoteIp, (remoteIps.get(result.remoteIp) || 0) + 1);
    } else {
      lastError = result.error || lastError;
    }
    if (i + 1 < TCP_SAMPLES) await sleep(40);
  }
  const requiredSuccesses = Math.max(1, Math.ceil(TCP_SAMPLES / 2));
  const remoteIp = [...remoteIps.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0] || "";
  return {
    ok: samples.length >= requiredSuccesses,
    latencyMs: median(samples),
    sampleCount: TCP_SAMPLES,
    successfulSamples: samples.length,
    remoteIp,
    error: samples.length >= requiredSuccesses ? "" : (lastError || "tcp samples failed"),
  };
}

async function tlsProbe(host, port, serverName, insecure) {
  const started = Date.now();
  return await new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect({
      host,
      port: Number(port),
      servername: serverName || undefined,
      rejectUnauthorized: !insecure,
    });
    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(TLS_TIMEOUT_MS);
    socket.once("secureConnect", () => finish({ ok: true, latencyMs: Math.max(1, Date.now() - started), error: "" }));
    socket.once("timeout", () => finish({ ok: false, latencyMs: 0, error: "tls timeout" }));
    socket.once("error", (error) => finish({
      ok: false,
      latencyMs: 0,
      error: String(error?.code || error?.message || "tls error").slice(0, 120),
    }));
  });
}

async function lookupCountries(ips) {
  const result = new Map();
  const unique = [...new Set(ips.filter(isPublicIp))];

  for (let i = 0; i < unique.length; i += COUNTRY_BATCH_SIZE) {
    const chunk = unique.slice(i, i + COUNTRY_BATCH_SIZE);
    let response;
    try {
      response = await fetchJson("https://api.country.is/?fields=asn", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(chunk),
      }, 3);
    } catch (error) {
      console.warn(`Country lookup batch failed: ${error.message}`);
      continue;
    }

    const rows = response.data;
    if (!Array.isArray(rows)) continue;
    for (const row of rows) {
      const ip = normalizeHost(row?.ip);
      const country = String(row?.country || "").toUpperCase();
      if (!isPublicIp(ip) || !/^[A-Z]{2}$/.test(country)) continue;
      result.set(ip, {
        country,
        org: String(row?.asn?.organization || "").slice(0, 160),
        ip,
        geoSource: "country-is",
        countryConfidence: "medium",
      });
    }
    if (i + COUNTRY_BATCH_SIZE < unique.length) await sleep(150);
  }

  return result;
}

async function resolveHostHttpsFallback(host) {
  const normalized = normalizeHost(host);
  if (!normalized || net.isIP(normalized)) return isPublicIp(normalized) ? normalized : "";

  const providers = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(normalized)}&type=A`,
    `https://dns.google/resolve?name=${encodeURIComponent(normalized)}&type=A`,
  ];

  for (const url of providers) {
    try {
      const response = await fetchJson(url, { headers: { accept: "application/dns-json" } }, 2);
      const answers = Array.isArray(response.data?.Answer) ? response.data.Answer : [];
      const ips = answers
        .map((row) => normalizeHost(row?.data || ""))
        .filter(isPublicIp)
        .sort();
      if (ips.length) return ips[0];
    } catch {}
  }
  return "";
}

async function buildLegacyFallback(items) {
  const hostMap = new Map();
  for (const item of items) {
    const host = normalizeHost(item?.host);
    if (!host || hostMap.has(host)) continue;
    hostMap.set(host, item);
  }

  const hosts = [...hostMap.keys()].slice(0, LEGACY_GEO_MAX_PER_RUN);
  if (!hosts.length) return new Map();

  console.log(`HTTPS fallback geolocation for ${hosts.length} unresolved hosts...`);
  const resolved = await mapLimit(hosts, LEGACY_GEO_CONCURRENCY, async (host) => ({
    host,
    ip: await resolveHostHttpsFallback(host),
  }));

  const countryByIp = await lookupCountries(resolved.map((row) => row?.ip).filter(isPublicIp));
  const result = new Map();
  for (const row of resolved) {
    if (!row?.host || !isPublicIp(row.ip)) continue;
    const geo = countryByIp.get(row.ip);
    if (!geo?.country) continue;
    result.set(row.host, {
      ...geo,
      ip: row.ip,
      geoSource: "https-doh-fallback",
      countryConfidence: "medium",
    });
  }
  return result;
}

function getParam(params, ...names) {
  for (const name of names) {
    const value = params.get(name);
    if (value !== null && value !== "") return value;
  }
  return "";
}

function normalizeTransportName(value) {
  const name = String(value || "").toLowerCase();
  if (["websocket", "ws"].includes(name)) return "ws";
  if (["grpc", "gun"].includes(name)) return "grpc";
  if (["httpupgrade", "http-upgrade", "upgrade"].includes(name)) return "httpupgrade";
  if (["http", "h2"].includes(name)) return "http";
  if (name === "quic") return "quic";
  return "";
}

function rawTransportName(params, fallback = {}) {
  return String(getParam(params, "type", "network", "net") || fallback.net || fallback.network || "").toLowerCase();
}

function isTransportSupported(params, fallback = {}) {
  const raw = rawTransportName(params, fallback);
  if (!raw || ["tcp", "none", "ws", "websocket", "grpc", "gun", "httpupgrade", "http-upgrade", "upgrade", "http", "h2", "quic"].includes(raw)) return true;
  return false;
}

function buildTransport(params, fallback = {}) {
  const raw = rawTransportName(params, fallback);
  const headerType = String(getParam(params, "headerType", "header", "headertype") || fallback.type || fallback.headerType || "").toLowerCase();
  let type = normalizeTransportName(raw);
  if ((!raw || raw === "tcp" || raw === "none") && headerType === "http") type = "http";
  const host = decodeURIComponentSafe(getParam(params, "host", "authority") || fallback.host || "");
  const pathValue = decodeURIComponentSafe(getParam(params, "path") || fallback.path || "");
  const pathText = pathValue || "/";

  if (type === "ws") {
    const transport = { type: "ws", path: pathText };
    if (host) transport.headers = { Host: host };
    const ed = Number(getParam(params, "ed", "early_data") || 0);
    if (Number.isFinite(ed) && ed > 0) {
      transport.max_early_data = Math.min(65535, Math.floor(ed));
      transport.early_data_header_name = "Sec-WebSocket-Protocol";
    }
    return transport;
  }
  if (type === "grpc") {
    return {
      type: "grpc",
      service_name: decodeURIComponentSafe(getParam(params, "serviceName", "service_name") || pathValue || fallback.path || ""),
    };
  }
  if (type === "httpupgrade") {
    const transport = { type: "httpupgrade", path: pathText };
    if (host) transport.host = host;
    return transport;
  }
  if (type === "http") {
    const transport = { type: "http", path: pathText };
    if (host) transport.host = splitList(host);
    return transport;
  }
  if (type === "quic") return { type: "quic" };
  return null;
}

function buildTls(params, fallback = {}, options = {}) {
  const security = String(getParam(params, "security") || fallback.security || fallback.tls || "").toLowerCase();
  const reality = security === "reality";
  const enabled = options.required || reality || security === "tls" || boolParam(getParam(params, "tls"));
  if (!enabled) return { tls: null, meta: { required: false, reality: false, serverName: "", insecure: false } };

  const serverName = decodeURIComponentSafe(
    getParam(params, "sni", "servername", "server_name", "peer") || fallback.sni || fallback.serverName || options.defaultServerName || ""
  );
  const insecure = boolParam(getParam(params, "allowInsecure", "allow_insecure", "insecure")) || boolParam(fallback.allowInsecure);
  const tlsConfig = {
    enabled: true,
    insecure,
  };
  if (serverName) tlsConfig.server_name = serverName;

  const alpn = splitList(getParam(params, "alpn") || fallback.alpn || "");
  if (alpn.length) tlsConfig.alpn = alpn;

  const fp = String(getParam(params, "fp", "fingerprint") || fallback.fp || "").toLowerCase();
  if (fp && U_TLS_FINGERPRINTS.has(fp)) tlsConfig.utls = { enabled: true, fingerprint: fp };

  if (reality) {
    const publicKey = decodeURIComponentSafe(getParam(params, "pbk", "publicKey", "public_key"));
    const shortId = decodeURIComponentSafe(getParam(params, "sid", "shortId", "short_id"));
    if (!publicKey) return { tls: null, meta: { required: true, reality: true, serverName, insecure, invalid: "missing reality public key" } };
    tlsConfig.reality = { enabled: true, public_key: publicKey, short_id: shortId || "" };
  }

  return { tls: tlsConfig, meta: { required: true, reality, serverName, insecure } };
}

function parseUrlConfig(raw) {
  try { return new URL(stripFragment(raw)); }
  catch { return null; }
}

function parseVless(raw, item) {
  const url = parseUrlConfig(raw);
  if (!url) return { supported: false, reason: "invalid vless URL" };
  const params = url.searchParams;
  if (!isTransportSupported(params)) return { supported: false, reason: "unsupported vless transport" };
  const uuid = decodeURIComponentSafe(url.username);
  if (!uuid) return { supported: false, reason: "missing vless uuid" };
  const server = item.ip || normalizeHost(url.hostname || item.host);
  const port = Number(url.port || item.port);
  const tlsInfo = buildTls(params, {}, { defaultServerName: net.isIP(url.hostname) ? "" : url.hostname });
  if (tlsInfo.meta.invalid) return { supported: false, reason: tlsInfo.meta.invalid, tlsMeta: tlsInfo.meta };
  const outbound = { type: "vless", tag: "proxy", server, server_port: port, uuid };
  const flow = decodeURIComponentSafe(getParam(params, "flow"));
  if (flow) outbound.flow = flow;
  if (tlsInfo.tls) outbound.tls = tlsInfo.tls;
  const transport = buildTransport(params);
  if (transport) outbound.transport = transport;
  return { supported: true, outbound, tlsMeta: tlsInfo.meta };
}

function parseVmess(raw, item) {
  try {
    const body = stripFragment(raw).slice(raw.indexOf("://") + 3);
    const data = JSON.parse(decodeBase64Flexible(body));
    const params = new URLSearchParams();
    if (!isTransportSupported(params, data)) return { supported: false, reason: "unsupported vmess transport" };
    const serverHost = normalizeHost(data.add || data.host || item.host);
    const server = item.ip || serverHost;
    const port = Number(data.port || item.port);
    const uuid = String(data.id || data.uuid || "").trim();
    if (!server || !port || !uuid) return { supported: false, reason: "invalid vmess fields" };
    const tlsInfo = buildTls(params, {
      security: data.tls || "",
      sni: data.sni || "",
      alpn: data.alpn || "",
      fp: data.fp || "",
      allowInsecure: data.allowInsecure || data.insecure || "",
    }, { defaultServerName: net.isIP(serverHost) ? "" : serverHost });
    const outbound = {
      type: "vmess",
      tag: "proxy",
      server,
      server_port: port,
      uuid,
      security: String(data.scy || data.security || "auto").toLowerCase() || "auto",
      alter_id: Number.isFinite(Number(data.aid)) ? Number(data.aid) : 0,
    };
    if (tlsInfo.tls) outbound.tls = tlsInfo.tls;
    const transport = buildTransport(params, data);
    if (transport) outbound.transport = transport;
    return { supported: true, outbound, tlsMeta: tlsInfo.meta };
  } catch {
    return { supported: false, reason: "invalid vmess payload" };
  }
}

function parseTrojan(raw, item) {
  const url = parseUrlConfig(raw);
  if (!url) return { supported: false, reason: "invalid trojan URL" };
  const params = url.searchParams;
  if (!isTransportSupported(params)) return { supported: false, reason: "unsupported trojan transport" };
  const password = decodeURIComponentSafe(url.username || url.password);
  if (!password) return { supported: false, reason: "missing trojan password" };
  const serverHost = normalizeHost(url.hostname || item.host);
  const server = item.ip || serverHost;
  const port = Number(url.port || item.port);
  const tlsInfo = buildTls(params, {}, { required: true, defaultServerName: net.isIP(serverHost) ? "" : serverHost });
  if (tlsInfo.meta.invalid) return { supported: false, reason: tlsInfo.meta.invalid, tlsMeta: tlsInfo.meta };
  const outbound = { type: "trojan", tag: "proxy", server, server_port: port, password };
  outbound.tls = tlsInfo.tls;
  const transport = buildTransport(params);
  if (transport) outbound.transport = transport;
  return { supported: true, outbound, tlsMeta: tlsInfo.meta };
}

function parseShadowsocks(raw, item) {
  try {
    const body = stripFragment(raw).slice(raw.indexOf("://") + 3);
    const qIndex = body.indexOf("?");
    const main = qIndex >= 0 ? body.slice(0, qIndex) : body;
    const query = qIndex >= 0 ? body.slice(qIndex + 1) : "";
    const params = new URLSearchParams(query);
    let credentials = "";
    let hostPort = "";
    const at = main.lastIndexOf("@");
    if (at >= 0) {
      credentials = decodeURIComponentSafe(main.slice(0, at));
      hostPort = main.slice(at + 1);
      if (!credentials.includes(":")) credentials = decodeBase64Flexible(credentials);
    } else {
      const decoded = decodeBase64Flexible(main);
      const decodedAt = decoded.lastIndexOf("@");
      if (decodedAt < 0) return { supported: false, reason: "invalid shadowsocks payload" };
      credentials = decoded.slice(0, decodedAt);
      hostPort = decoded.slice(decodedAt + 1);
    }
    const colon = credentials.indexOf(":");
    if (colon <= 0) return { supported: false, reason: "invalid shadowsocks credentials" };
    const method = credentials.slice(0, colon);
    const password = credentials.slice(colon + 1);
    const portColon = hostPort.lastIndexOf(":");
    if (portColon <= 0) return { supported: false, reason: "invalid shadowsocks endpoint" };
    const originalHost = normalizeHost(hostPort.slice(0, portColon));
    const server = item.ip || originalHost;
    const port = Number(hostPort.slice(portColon + 1) || item.port);
    const outbound = { type: "shadowsocks", tag: "proxy", server, server_port: port, method, password };
    const pluginRaw = decodeURIComponentSafe(getParam(params, "plugin"));
    if (pluginRaw) {
      const [plugin, ...opts] = pluginRaw.split(";");
      if (["obfs-local", "v2ray-plugin"].includes(plugin)) {
        outbound.plugin = plugin;
        outbound.plugin_opts = opts.join(";");
      }
    }
    return { supported: true, outbound, tlsMeta: { required: false, reality: false, serverName: "", insecure: false } };
  } catch {
    return { supported: false, reason: "invalid shadowsocks URL" };
  }
}

function parseHysteria2(raw, item) {
  const url = parseUrlConfig(raw);
  if (!url) return { supported: false, reason: "invalid hysteria2 URL" };
  const params = url.searchParams;
  const hyUser = decodeURIComponentSafe(url.username);
  const hyPass = decodeURIComponentSafe(url.password);
  const password = hyUser && hyPass ? `${hyUser}:${hyPass}` : (hyUser || hyPass);
  if (!password) return { supported: false, reason: "missing hysteria2 password" };
  const serverHost = normalizeHost(url.hostname || item.host);
  const server = item.ip || serverHost;
  const port = Number(url.port || item.port);
  const tlsInfo = buildTls(params, {}, { required: true, defaultServerName: net.isIP(serverHost) ? "" : serverHost });
  const outbound = { type: "hysteria2", tag: "proxy", server, server_port: port, password, tls: tlsInfo.tls };
  const obfsType = String(getParam(params, "obfs")).toLowerCase();
  const obfsPassword = decodeURIComponentSafe(getParam(params, "obfs-password", "obfs_password"));
  if (obfsType && obfsPassword && ["salamander", "gecko"].includes(obfsType)) {
    outbound.obfs = { type: obfsType, password: obfsPassword };
  }
  return { supported: true, outbound, tlsMeta: { ...tlsInfo.meta, quic: true } };
}

function parseTuic(raw, item) {
  const url = parseUrlConfig(raw);
  if (!url) return { supported: false, reason: "invalid tuic URL" };
  const params = url.searchParams;
  const uuid = decodeURIComponentSafe(url.username);
  const password = decodeURIComponentSafe(url.password);
  if (!uuid || !password) return { supported: false, reason: "missing tuic credentials" };
  const serverHost = normalizeHost(url.hostname || item.host);
  const server = item.ip || serverHost;
  const port = Number(url.port || item.port);
  const tlsInfo = buildTls(params, {}, { required: true, defaultServerName: net.isIP(serverHost) ? "" : serverHost });
  const outbound = { type: "tuic", tag: "proxy", server, server_port: port, uuid, password, tls: tlsInfo.tls };
  const cc = String(getParam(params, "congestion_control", "congestion-control")).toLowerCase();
  if (["cubic", "new_reno", "bbr"].includes(cc)) outbound.congestion_control = cc;
  return { supported: true, outbound, tlsMeta: { ...tlsInfo.meta, quic: true } };
}

function parseProxyConfig(raw, item) {
  const protocol = normalizeProtocol(item.protocol || String(raw || "").split("://")[0]);
  if (!PROTOCOL_TEST_PROTOCOLS.has(protocol) || !raw) return { supported: false, reason: "protocol not supported by deep checker" };
  if (protocol === "vless") return parseVless(raw, item);
  if (protocol === "vmess") return parseVmess(raw, item);
  if (protocol === "trojan") return parseTrojan(raw, item);
  if (protocol === "ss") return parseShadowsocks(raw, item);
  if (protocol === "hysteria2") return parseHysteria2(raw, item);
  if (protocol === "tuic") return parseTuic(raw, item);
  return { supported: false, reason: "protocol parser unavailable" };
}

async function getFreePort() {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const port = await new Promise((resolve, reject) => {
      const server = net.createServer();
      server.unref();
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        const selected = typeof address === "object" && address ? address.port : 0;
        server.close((error) => error ? reject(error) : resolve(selected));
      });
    });
    if (!port || RESERVED_LOCAL_PORTS.has(port)) continue;
    RESERVED_LOCAL_PORTS.add(port);
    return port;
  }
  throw new Error("Unable to reserve a unique local port");
}

function releaseFreePort(port) {
  RESERVED_LOCAL_PORTS.delete(Number(port));
}

function isBindConflict(value) {
  return /address already in use|eaddrinuse|bind.*failed|listen.*failed/i.test(String(value || ""));
}

async function waitForPort(port, child, timeoutMs = 2500) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) return false;
    const ok = await new Promise((resolve) => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      const finish = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(250);
      socket.once("connect", () => finish(true));
      socket.once("timeout", () => finish(false));
      socket.once("error", () => finish(false));
    });
    if (ok) return true;
    await sleep(80);
  }
  return false;
}

async function runCommand(command, args, timeoutMs) {
  return await new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => {
      try { child.kill("SIGKILL"); } catch {}
    }, timeoutMs);
    child.stderr.on("data", (chunk) => {
      if (stderr.length < 4000) stderr += chunk.toString("utf8");
    });
    child.once("error", (error) => finish({ code: -1, stderr: String(error?.message || error) }));
    child.once("exit", (code) => finish({ code: Number.isInteger(code) ? code : -1, stderr: stderr.slice(-1000) }));
  });
}

async function deepProtocolProbeOnPort(item, parsed, port) {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "papa-vpn-"));
  const configPath = path.join(tempDir, "config.json");
  const config = {
    log: { disabled: true },
    inbounds: [{ type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: port }],
    outbounds: [parsed.outbound],
    route: { final: "proxy" },
  };

  let child = null;
  const started = Date.now();
  try {
    await fs.writeFile(configPath, JSON.stringify(config), "utf8");
    const checked = await runCommand(SING_BOX_BIN, ["check", "-c", configPath], 4000);
    if (checked.code !== 0) {
      return {
        tested: false,
        ok: false,
        bindConflict: false,
        latencyMs: 0,
        error: `sing-box config unsupported: ${checked.stderr || checked.code}`.slice(0, 120),
        tlsMeta: parsed.tlsMeta,
      };
    }

    child = spawn(SING_BOX_BIN, ["run", "-c", configPath], { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      if (stderr.length < 4000) stderr += chunk.toString("utf8");
    });

    const ready = await waitForPort(port, child, 2500);
    if (!ready) {
      const message = `sing-box startup failed: ${stderr || child.exitCode || "not ready"}`.slice(0, 120);
      return {
        tested: false,
        ok: false,
        bindConflict: isBindConflict(message),
        latencyMs: 0,
        error: message,
        tlsMeta: parsed.tlsMeta,
      };
    }

    const curl = await runCommand("curl", [
      "-sS",
      "--socks5-hostname", `127.0.0.1:${port}`,
      "--connect-timeout", String(Math.max(2, Math.ceil(PROTOCOL_TIMEOUT_MS / 2000))),
      "--max-time", String(Math.max(4, Math.ceil(PROTOCOL_TIMEOUT_MS / 1000))),
      "-o", "/dev/null",
      TEST_URL,
    ], PROTOCOL_TIMEOUT_MS + 1500);

    return {
      tested: true,
      ok: curl.code === 0,
      bindConflict: false,
      latencyMs: curl.code === 0 ? Math.max(1, Date.now() - started) : 0,
      error: curl.code === 0 ? "" : `protocol request failed: ${curl.stderr || `exit ${curl.code}`}`.slice(0, 120),
      tlsMeta: parsed.tlsMeta,
    };
  } catch (error) {
    const message = String(error?.message || error).slice(0, 120);
    return {
      tested: false,
      ok: false,
      bindConflict: isBindConflict(message),
      latencyMs: 0,
      error: message,
      tlsMeta: parsed.tlsMeta,
    };
  } finally {
    if (child && child.exitCode === null) {
      try { child.kill("SIGTERM"); } catch {}
      await sleep(30);
      if (child.exitCode === null) { try { child.kill("SIGKILL"); } catch {} }
    }
    try { await fs.rm(tempDir, { recursive: true, force: true }); } catch {}
  }
}

async function deepProtocolProbe(item) {
  const parsed = parseProxyConfig(item.raw, item);
  if (!parsed.supported) {
    return {
      tested: false,
      ok: false,
      latencyMs: 0,
      error: parsed.reason || "deep parser unavailable",
      tlsMeta: parsed.tlsMeta || null,
    };
  }

  let lastResult = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const port = await getFreePort();
    try {
      const result = await deepProtocolProbeOnPort(item, parsed, port);
      lastResult = result;
      if (!result.bindConflict) {
        const { bindConflict, ...publicResult } = result;
        return publicResult;
      }
    } finally {
      releaseFreePort(port);
    }
    await sleep(50 * attempt);
  }

  return {
    tested: false,
    ok: false,
    latencyMs: 0,
    error: (lastResult?.error || "local proxy port allocation failed").slice(0, 120),
    tlsMeta: parsed.tlsMeta || null,
  };
}

async function main() {
  console.log("Fetching health export from Worker...");
  const exportedResponse = await fetchJson(`${WORKER_URL}/health/export`, {
    headers: { authorization: `Bearer ${HEALTH_SECRET}`, accept: "application/json" },
  }, 4);
  const exported = exportedResponse.data;

  const items = Array.isArray(exported.items) ? exported.items : [];
  console.log(`Received ${items.length} unique endpoints; generation=${exported.generation || "unknown"}`);
  if (!items.length) return;

  console.time("stage:dns-tcp");
  const endpointRows = await mapLimit(items, ENDPOINT_CONCURRENCY, async (rawItem) => {
    const resolved = await resolveHost(rawItem.host);
    const item = {
      ...rawItem,
      ...resolved,
      currentCountry: String(rawItem.currentCountry || "").toUpperCase(),
      currentLocationConfidence: String(rawItem.currentLocationConfidence || "unknown").toLowerCase(),
      currentGeoSource: String(rawItem.currentGeoSource || "stored"),
    };

    const protocol = normalizeProtocol(item.protocol);
    let endpointHealth;
    if (TCP_PROTOCOLS.has(protocol)) {
      endpointHealth = await tcpProbeSamples(item.host, item.port);
    } else if (PROTOCOL_TEST_PROTOCOLS.has(protocol)) {
      endpointHealth = {
        ok: false, testable: false, latencyMs: 0, sampleCount: 0,
        successfulSamples: 0, remoteIp: "", error: "deep protocol check required",
      };
    } else if (UDP_PROTOCOLS.has(protocol)) {
      endpointHealth = {
        ok: false, testable: false, latencyMs: 0, sampleCount: 0,
        successfulSamples: 0, remoteIp: "", error: "UDP protocol requires deep protocol support",
      };
    } else {
      endpointHealth = {
        ok: false, testable: false, latencyMs: 0, sampleCount: 0,
        successfulSamples: 0, remoteIp: "", error: "Unsupported probe protocol",
      };
    }

    const connectedIp = isPublicIp(normalizeHost(endpointHealth.remoteIp || ""))
      ? normalizeHost(endpointHealth.remoteIp)
      : "";
    const preferredGeoIp = connectedIp || (isPublicIp(item.ip) ? item.ip : "");
    const preferredGeoSource = net.isIP(normalizeHost(item.host))
      ? "direct-ip"
      : connectedIp ? "tcp-remote-ip" : item.geoSource;
    const preferredCountryConfidence =
      preferredGeoSource === "direct-ip" || preferredGeoSource === "tcp-remote-ip"
        ? "high"
        : preferredGeoIp ? "medium" : "unknown";

    return {
      ...item,
      endpointHealth,
      preferredGeoIp,
      preferredGeoSource,
      preferredCountryConfidence,
    };
  });
  console.timeEnd("stage:dns-tcp");

  const geoLookupIps = endpointRows.map((item) => item?.preferredGeoIp).filter(isPublicIp);
  console.log(`Resolving country for ${new Set(geoLookupIps).size} freshly resolved/connected IP addresses...`);
  console.time("stage:country-lookup");
  const countries = await lookupCountries(geoLookupIps);
  console.timeEnd("stage:country-lookup");

  const fallbackCandidates = endpointRows.filter((item) => {
    if (!item) return false;
    if (item.preferredGeoIp && countries.has(item.preferredGeoIp)) return false;
    return true;
  });

  console.time("stage:https-geo-fallback");
  const legacyFallback = await buildLegacyFallback(fallbackCandidates);
  console.timeEnd("stage:https-geo-fallback");

  console.log("Running deep protocol checks with sing-box where supported...");
  console.time("stage:deep-protocol");
  const deepRows = await mapLimit(endpointRows, PROTOCOL_CONCURRENCY, async (item) => {
    if (!item || !PROTOCOL_TEST_PROTOCOLS.has(normalizeProtocol(item.protocol)) || !item.raw) {
      return { ...item, protocolProbe: { tested: false, ok: false, latencyMs: 0, error: "not supported" } };
    }
    return { ...item, protocolProbe: await deepProtocolProbe(item) };
  });
  console.timeEnd("stage:deep-protocol");

  console.time("stage:tls-probe");
  const tlsRows = await mapLimit(deepRows, TCP_CONCURRENCY, async (item) => {
    if (!item) return item;
    const tlsMeta = item.protocolProbe?.tlsMeta || parseProxyConfig(item.raw, item)?.tlsMeta || null;
    if (!tlsMeta?.required || tlsMeta.reality || tlsMeta.quic) {
      return { ...item, tlsProbe: { tested: false, ok: false, latencyMs: 0, error: "" } };
    }
    const result = await tlsProbe(item.host, item.port, tlsMeta.serverName, tlsMeta.insecure);
    return { ...item, tlsProbe: { tested: true, ...result } };
  });
  console.timeEnd("stage:tls-probe");

  const probeRows = tlsRows.map((item) => {
    if (!item) return null;
    const endpoint = item.endpointHealth || {};
    const deep = item.protocolProbe || {};
    const tlsResult = item.tlsProbe || {};

    let testable = endpoint.testable !== false || deep.tested === true;
    let finalOk = false;
    let probeLevel = "unchecked";
    let error = "";
    let latencyMs = 0;

    if (deep.tested) {
      finalOk = deep.ok === true;
      probeLevel = "protocol";
      latencyMs = deep.latencyMs || endpoint.latencyMs || 0;
      error = deep.error || "";
    } else if (endpoint.testable !== false) {
      finalOk = endpoint.ok === true;
      probeLevel = "tcp";
      latencyMs = endpoint.latencyMs || 0;
      error = endpoint.error || deep.error || "";
    } else {
      testable = false;
      probeLevel = "unverified";
      error = deep.error || endpoint.error || "not testable";
    }

    let geo = null;
    if (item.preferredGeoIp) {
      const fresh = countries.get(item.preferredGeoIp) || null;
      if (fresh) {
        geo = {
          ...fresh,
          ip: item.preferredGeoIp,
          geoSource: item.preferredGeoSource || "dns",
          countryConfidence: item.preferredCountryConfidence || "medium",
        };
      }
    }
    if (!geo) geo = legacyFallback.get(normalizeHost(item.host)) || null;
    if (!geo && /^[A-Z]{2}$/.test(String(item.currentCountry || "").toUpperCase())) {
      geo = {
        country: String(item.currentCountry).toUpperCase(),
        org: "",
        ip: item.currentGeoIp || item.preferredGeoIp || item.ip || "",
        geoSource: item.currentGeoSource || (item.currentLocationConfidence === "low" ? "source-label" : "stored"),
        countryConfidence: item.currentLocationConfidence || "low",
      };
    }

    return {
      fingerprint: item.fingerprint,
      testable,
      ok: finalOk,
      latencyMs,
      sampleCount: endpoint.sampleCount || 0,
      sampleSuccessRate: endpoint.sampleCount
        ? Math.round(((endpoint.successfulSamples || 0) / endpoint.sampleCount) * 10000) / 10000
        : (deep.tested ? (deep.ok ? 1 : 0) : 0),
      error,
      protocolTested: deep.tested === true,
      protocolOk: deep.tested === true && deep.ok === true,
      tlsTested: tlsResult.tested === true,
      tlsOk: tlsResult.tested === true && tlsResult.ok === true,
      probeLevel,
      ip: geo?.ip || item.preferredGeoIp || item.ip || "",
      country: geo?.country || "",
      countryConfidence: geo?.countryConfidence || item.currentLocationConfidence || "unknown",
      org: geo?.org || "",
      geoSource: geo?.geoSource || item.preferredGeoSource || item.currentGeoSource || "none",
    };
  });

  const results = probeRows.filter((row) => row?.fingerprint);
  const healthy = results.filter((row) => row.testable && row.ok).length;
  const failed = results.filter((row) => row.testable && !row.ok).length;
  const untestable = results.filter((row) => !row.testable).length;
  const protocolTested = results.filter((row) => row.protocolTested).length;
  const protocolHealthy = results.filter((row) => row.protocolTested && row.protocolOk).length;
  const tlsTested = results.filter((row) => row.tlsTested).length;
  const tlsHealthy = results.filter((row) => row.tlsTested && row.tlsOk).length;
  const located = results.filter((row) => /^[A-Z]{2}$/.test(row.country)).length;
  const unresolved = results.length - located;
  const fallbackLocated = results.filter((row) => row.geoSource === "https-doh-fallback" && /^[A-Z]{2}$/.test(row.country)).length;

  console.log(
    `Health result: healthy=${healthy}, failed=${failed}, untestable=${untestable}, ` +
    `protocol=${protocolHealthy}/${protocolTested}, tls=${tlsHealthy}/${tlsTested}, ` +
    `located=${located}/${results.length}, unresolved=${unresolved}, httpsFallbackLocated=${fallbackLocated}`
  );

  const payload = {
    generation: exported.generation || "",
    checkedAt: Date.now(),
    runner: "github-actions-sing-box",
    results,
  };

  let lastError;
  const maxReportAttempts = 10;
  for (let attempt = 1; attempt <= maxReportAttempts; attempt += 1) {
    try {
      const reportResponse = await fetchJson(`${WORKER_URL}/health/report`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${HEALTH_SECRET}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify(payload),
      }, 1);
      console.log("Worker accepted report:", JSON.stringify(reportResponse.data));
      return;
    } catch (error) {
      lastError = error;
      const status = Number(error?.status);
      const networkFailure = !Number.isFinite(status) || status <= 0;
      const generationChanged = status === 409 && /generation/i.test(error?.message || "");
      if (generationChanged) {
        console.log("Generation changed while this health run was executing. Skipping this stale report; the next run will test the new bank.");
        return;
      }

      const retryable = networkFailure || status === 409 || isTransientStatus(status);
      if (!retryable || attempt >= maxReportAttempts) break;

      const exponential = Math.min(60000, 2000 * (2 ** Math.min(5, attempt - 1)));
      const waitMs = retryAfterMsFrom(error, exponential + Math.floor(Math.random() * 1000));
      console.log(
        `Health report failed${status ? ` with HTTP ${status}` : ""}; ` +
        `retrying in ${Math.ceil(waitMs / 1000)}s (${attempt}/${maxReportAttempts})...`
      );
      await sleep(waitMs);
    }
  }

  throw lastError;
}
main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
