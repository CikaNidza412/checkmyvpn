// functions/api/ip.js

function getClientIp(req) {
  return (
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown"
  );
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

async function fetchWithTimeout(url, opts = {}, timeoutMs = 4500) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(id);
  }
}

// Cache: smanji broj poziva ka ipapi.is (bitno za free limit)
async function cachedJson(request, cacheKeyUrl, ttlSeconds, fetcher) {
  const cache = caches.default;
  const cacheKey = new Request(cacheKeyUrl, { method: "GET" });

  const hit = await cache.match(cacheKey);
  if (hit) return hit;

  const fresh = await fetcher();
  const cloned = fresh.clone();

  // “edge cache” za smanjenje poziva; response i dalje ima cache-control:no-store za browser
  const headers = new Headers(cloned.headers);
  headers.set("cache-control", `public, max-age=${ttlSeconds}`);
  const cachedResponse = new Response(await cloned.arrayBuffer(), {
    status: cloned.status,
    headers,
  });

  await cache.put(cacheKey, cachedResponse);
  return fresh;
}

export async function onRequest(context) {
  const req = context.request;
  const cf = req.cf || {};
  const ip = getClientIp(req);

  // CF baseline (fallback)
  const cfLocationParts = [cf.city, cf.region, cf.country].filter(Boolean).join(", ");
  const cfLocation = cf.timezone ? `${cfLocationParts} (${cf.timezone})` : (cfLocationParts || "unknown");
  const cfAsn = cf.asn ? `AS${cf.asn}` : "";
  const cfOrg = cf.asOrganization || "";
  const cfAsnStr = [cfAsn, cfOrg].filter(Boolean).join(" ").trim() || "unknown";

  const baseline = {
    ip,
    source: "cloudflare",
    location: cfLocation,
    country: cf.country || null,
    region: cf.region || null,
    city: cf.city || null,
    timezone: cf.timezone || null,
    asn: cf.asn || null,
    asOrganization: cf.asOrganization || null,
    security: {
      isAnonymousProxy: !!cf.isAnonymousProxy,
    },
  };

  // Ako nemamo IP, vrati fallback
  if (!ip || ip === "unknown") {
    return json({
      ok: true,
      ...baseline,
      verdict: {
        vpnLikely: false,
        reason: "IP unknown",
      },
    });
  }

  // ipapi.is (preciznije za VPN/datacenter)
  // Docs: https://api.ipapi.is?q=... (+ optional &key=...) :contentReference[oaicite:1]{index=1}
  const apiKey = context.env?.IPAPI_KEY || ""; // opcionalno (setuj u Cloudflare Pages vars)
  const url = new URL("https://api.ipapi.is");
  url.searchParams.set("q", ip);
  if (apiKey) url.searchParams.set("key", apiKey);

  // cache key (bez key-a u URL-u)
  const cacheKeyUrl = `https://cache.checkmyvpn.local/ipapi?q=${encodeURIComponent(ip)}`;

  try {
    const res = await cachedJson(req, cacheKeyUrl, 300, async () => {
      return fetchWithTimeout(url.toString(), {
        headers: { "accept": "application/json" },
      }, 4500);
    });

    if (!res.ok) {
      // fallback ako api vrati 4xx/5xx
      return json({
        ok: true,
        ...baseline,
        ipapi: { ok: false, status: res.status },
        verdict: {
          vpnLikely: baseline.security.isAnonymousProxy,
          reason: baseline.security.isAnonymousProxy ? "Cloudflare anonymous proxy flag" : "ipapi unavailable",
        },
      });
    }

    const data = await res.json();

    // ipapi.is tipična polja (zavisi od response-a):
    // location: country, region, city, latitude, longitude, timezone...
    // asn/company: asn, org/name/domain/type...
    // security flags: is_vpn, is_proxy, is_tor, is_datacenter, is_abuser, ...
    const geo = data.location || {};
    const asnObj = data.asn || {};
    const company = data.company || {};
    const sec = data.security || {};

    const country = geo.country_code || geo.country || null;
    const region = geo.region || null;
    const city = geo.city || null;
    const timezone = geo.timezone || null;

    const locationParts = [city, region, country].filter(Boolean).join(", ") || "unknown";
    const location = timezone ? `${locationParts} (${timezone})` : locationParts;

    // ASN string
    const asnNumber = asnObj.asn ? `AS${asnObj.asn}` : "";
    const asnName = asnObj.org || asnObj.name || company.name || "";
    const asnType = company.type || asnObj.type || ""; // hosting/isp/business...
    const asnStr = [asnNumber, asnName].filter(Boolean).join(" ").trim() || "unknown";

    // “VPN verdict”
    const flags = {
      is_vpn: !!sec.is_vpn,
      is_proxy: !!sec.is_proxy,
      is_tor: !!sec.is_tor,
      is_datacenter: !!sec.is_datacenter,
      is_abuser: !!sec.is_abuser,
    };

    const vpnLikely =
      flags.is_vpn ||
      flags.is_proxy ||
      flags.is_tor ||
      flags.is_datacenter ||
      baseline.security.isAnonymousProxy;

    const mismatch =
      (baseline.country && country && baseline.country !== country) ? {
        cloudflareCountry: baseline.country,
        ipapiCountry: country,
      } : null;

    const reasons = [];
    if (flags.is_vpn) reasons.push("ipapi: is_vpn");
    if (flags.is_proxy) reasons.push("ipapi: is_proxy");
    if (flags.is_tor) reasons.push("ipapi: is_tor");
    if (flags.is_datacenter) reasons.push("ipapi: is_datacenter");
    if (baseline.security.isAnonymousProxy) reasons.push("cloudflare: isAnonymousProxy");
    if (!reasons.length) reasons.push("no strong signal");

    return json({
      ok: true,
      ip,
      source: "ipapi+cloudflare",
      location,
      country,
      region,
      city,
      timezone,
      asn: asnStr,
      asnType: asnType || null,
      flags,
      countryMismatch: mismatch,
      // dodatno: pokaži i CF kao referencu
      cloudflare: {
        location: baseline.location,
        country: baseline.country,
        asn: baseline.asOrganization ? `AS${baseline.asn} ${baseline.asOrganization}` : baseline.asnStr,
      },
      verdict: {
        vpnLikely,
        reasons,
      },
    });
  } catch (e) {
    // timeout / abort / json parse fail → fallback
    return json({
      ok: true,
      ...baseline,
      ipapi: { ok: false, error: "fetch_failed" },
      verdict: {
        vpnLikely: baseline.security.isAnonymousProxy,
        reason: baseline.security.isAnonymousProxy ? "Cloudflare anonymous proxy flag" : "ipapi fetch failed",
      },
    });
  }
}

