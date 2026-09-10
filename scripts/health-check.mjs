import dns from "node:dns/promises";
import net from "node:net";

const WORKER_URL = String(process.env.WORKER_URL || "").replace(/\/+$/, "");
const HEALTH_SECRET = String(process.env.WORKER_HEALTH_SECRET || "");
const TCP_TIMEOUT_MS = Number(process.env.TCP_TIMEOUT_MS || 3500);
const DNS_TIMEOUT_MS = Number(process.env.DNS_TIMEOUT_MS || 3000);
const DNS_CONCURRENCY = Number(process.env.DNS_CONCURRENCY || 60);
const TCP_CONCURRENCY = Number(process.env.TCP_CONCURRENCY || 80);
const COUNTRY_BATCH_SIZE = 100;

if (!WORKER_URL || !/^https:\/\//i.test(WORKER_URL)) {
  throw new Error("WORKER_URL must be a valid https:// URL");
}
if (!HEALTH_SECRET) throw new Error("WORKER_HEALTH_SECRET is missing");

const TCP_PROTOCOLS = new Set(["vless", "vmess", "trojan", "ss", "ssr", "ssh"]);
const UDP_PROTOCOLS = new Set(["hysteria", "hysteria2", "tuic", "wireguard"]);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeHost(value) {
  return String(value || "").trim().replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
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

async function fetchJson(url, options = {}, retries = 3) {
  let lastError;
  for (let attempt = 1; attempt <= retries; attempt += 1) {
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
      try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
      if (!response.ok) {
        const error = new Error(`HTTP ${response.status}: ${data?.error || text || response.statusText}`);
        error.status = response.status;
        throw error;
      }
      return data;
    } catch (error) {
      lastError = error;
      if (attempt >= retries) break;
      await sleep(1500 * attempt);
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
    return isPublicIp(normalized) ? { ip: normalized, geoSource: "direct-ip" } : { ip: "", geoSource: "none" };
  }
  try {
    const rows = await withTimeout(dns.lookup(normalized, { all: true, verbatim: true }), DNS_TIMEOUT_MS, "DNS");
    const publicRows = rows.filter((row) => isPublicIp(row.address));
    publicRows.sort((a, b) => a.family - b.family || a.address.localeCompare(b.address));
    return publicRows.length ? { ip: publicRows[0].address, geoSource: "dns" } : { ip: "", geoSource: "none" };
  } catch {
    return { ip: "", geoSource: "none" };
  }
}

async function tcpProbe(host, port) {
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
    socket.once("connect", () => finish({ ok: true, latencyMs: Math.max(1, Date.now() - started), error: "" }));
    socket.once("timeout", () => finish({ ok: false, latencyMs: 0, error: "timeout" }));
    socket.once("error", (error) => finish({ ok: false, latencyMs: 0, error: String(error?.code || error?.message || "connection error").slice(0, 120) }));
  });
}

async function lookupCountries(ips) {
  const result = new Map();
  const unique = [...new Set(ips.filter(isPublicIp))];
  for (let i = 0; i < unique.length; i += COUNTRY_BATCH_SIZE) {
    const chunk = unique.slice(i, i + COUNTRY_BATCH_SIZE);
    let rows;
    try {
      rows = await fetchJson("https://api.country.is/?fields=asn", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(chunk),
      }, 3);
    } catch (error) {
      console.warn(`Country lookup batch failed: ${error.message}`);
      continue;
    }
    if (!Array.isArray(rows)) continue;
    for (const row of rows) {
      const ip = normalizeHost(row?.ip);
      const country = String(row?.country || "").toUpperCase();
      if (!isPublicIp(ip) || !/^[A-Z]{2}$/.test(country)) continue;
      result.set(ip, {
        country,
        org: String(row?.asn?.organization || "").slice(0, 160),
      });
    }
    if (i + COUNTRY_BATCH_SIZE < unique.length) await sleep(150);
  }
  return result;
}

async function main() {
  console.log("Fetching health export from Worker...");
  const exported = await fetchJson(`${WORKER_URL}/health/export`, {
    headers: { authorization: `Bearer ${HEALTH_SECRET}`, accept: "application/json" },
  }, 4);

  const items = Array.isArray(exported.items) ? exported.items : [];
  console.log(`Received ${items.length} unique endpoints; generation=${exported.generation || "unknown"}`);
  if (!items.length) return;

  const resolvedRows = await mapLimit(items, DNS_CONCURRENCY, async (item) => {
    const resolved = item.currentCountry && item.currentGeoIp && isPublicIp(item.currentGeoIp)
      ? { ip: item.currentGeoIp, geoSource: net.isIP(normalizeHost(item.host)) ? "direct-ip" : "dns" }
      : await resolveHost(item.host);
    return { ...item, ...resolved };
  });

  const missingCountryIps = resolvedRows
    .filter((item) => item?.ip && !item.currentCountry)
    .map((item) => item.ip);
  console.log(`Resolving country for ${new Set(missingCountryIps).size} IP addresses...`);
  const countries = await lookupCountries(missingCountryIps);

  const probeRows = await mapLimit(resolvedRows, TCP_CONCURRENCY, async (item) => {
    const protocol = String(item.protocol || "").toLowerCase();
    let health;
    if (TCP_PROTOCOLS.has(protocol)) {
      health = await tcpProbe(item.host, item.port);
    } else if (UDP_PROTOCOLS.has(protocol)) {
      health = { ok: false, testable: false, latencyMs: 0, error: "UDP protocol not TCP-probed" };
    } else {
      health = { ok: false, testable: false, latencyMs: 0, error: "Unsupported probe protocol" };
    }

    const geo = item.currentCountry
      ? { country: item.currentCountry, org: "" }
      : (countries.get(item.ip) || { country: "", org: "" });

    return {
      fingerprint: item.fingerprint,
      testable: health.testable !== false,
      ok: health.ok === true,
      latencyMs: health.latencyMs || 0,
      error: health.error || "",
      ip: item.ip || "",
      country: geo.country || "",
      org: geo.org || "",
      geoSource: item.geoSource || "none",
    };
  });

  const results = probeRows.filter((row) => row?.fingerprint);
  const healthy = results.filter((row) => row.testable && row.ok).length;
  const failed = results.filter((row) => row.testable && !row.ok).length;
  const untestable = results.filter((row) => !row.testable).length;
  const located = results.filter((row) => /^[A-Z]{2}$/.test(row.country)).length;
  console.log(`Health result: healthy=${healthy}, failed=${failed}, untestable=${untestable}, located=${located}/${results.length}`);

  const payload = {
    generation: exported.generation || "",
    checkedAt: Date.now(),
    runner: "github-actions",
    results,
  };

  let lastError;
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    try {
      const report = await fetchJson(`${WORKER_URL}/health/report`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${HEALTH_SECRET}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify(payload),
      }, 1);
      console.log("Worker accepted report:", JSON.stringify(report));
      return;
    } catch (error) {
      lastError = error;
      if (error?.status !== 409 || attempt >= 5) break;
      console.log(`Worker busy or generation changed; refetching in 30s (${attempt}/5)...`);
      await sleep(30000);
      if (/generation/i.test(error.message || "")) {
        console.log("Generation changed. Ending this run; the next scheduled run will test the new bank.");
        return;
      }
    }
  }
  throw lastError;
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
