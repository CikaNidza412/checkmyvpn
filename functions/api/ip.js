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
      "cache-control": "no-store, max-age=0",
      "pragma": "no-cache",
      "expires": "0",
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

/*
  Edge cache:
  - Cloudflare može da kešira (s-maxage)
  - Browser nikad ne kešira (no-store)
*/
async function cachedJson(request, cacheKeyUrl, ttlSeconds, fetcher) {
  const cache = caches.default;
  const cacheKey = new Request(cacheKeyUrl, { method: "GET" });

  const hit = await cache.match(cacheKey);
  if (hit) {
    const body = await hit.arrayBuffer();
    const headers = new Headers(hit.headers);

    // Nikad ne dozvoli browser cache
    headers.set("cache-control", "no-store, max-age=0");
    headers.set("pragma", "no-cache");
    headers.set("expires", "0");

    return new Response(body, { status: hit.status, headers });
  }

  const fresh = await fetcher();
  const cloned = fresh.clone();
  const body = await cloned.arrayBuffer();
  const headers = new Headers(cloned.headers);

  // Edge cache only
  headers.set("cache-control", `public, s-maxage=${ttlSeconds}, max-age=0`);
  headers.set("cdn-cache-control", `public, s-maxage=${ttlSeconds}`);
  headers.set("cloudflare-cdn-cache-control", `public, s-maxage=${ttlSeconds}`);

  await cache.put(
    cacheKey,
    new Response(body, { status: cloned.status, headers })
  );

  // Browser dobija no-store
  const outHeaders = new Headers(fresh.headers);
  outHeaders.set("cache-control", "no-store, max-age=0");
  outHeaders.set("pragma", "no-cache");
  outHeaders.set("expires", "0");

  return new Response(await fresh.arrayBuffer(), {
    status: fresh.status,
    headers: outHeaders,
  });
}

export async function onRequest(context) {
  const req = context.request;
  const cf = req.cf || {};
  const ip = getClientIp(req);

  const cfLocationParts = [cf.city, cf.region, cf.country]
    .filter(Boolean)
    .join(", ");

  const cfLocation = cf.timezone
    ? `${cfLocationParts} (${cf.timezone})`
    : cfLocationParts || "unknown";

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

  const apiKey = context.env?.IPAPI_KEY || "";
  const url = new URL("https://api.ipapi.is");
  url.searchParams.set("q", ip);
  if (apiKey) url.searchParams.set("key", apiKey);

  const cacheKeyUrl = `https://cache.checkmyvpn.local/ipapi?q=${encodeURIComponent(ip)}`;

  try {
    const res = await cachedJson(req, cacheKeyUrl, 300, async () => {
      return fetchWithTimeout(url.toString(), {
        headers: { accept: "application/json" },
      });
    });

    if (!res.ok) {
      return json({
        ok: true,
        ...baseline,
        ipapi: { ok: false, status: res.status },
        verdict: {
          vpnLikely: baseline.security.isAnonymousProxy,
          reason: "ipapi unavailable",
        },
      });
    }

    const data = await res.json();

    const geo = data.location || {};
    const asnObj = data.asn || {};
    const company = data.company || {};
    const sec = data.security || {};

    const country = geo.country_code || geo.country || null;
    const region = geo.region || null;
    const city = geo.city || null;
    const timezone = geo.timezone || null;

    const locationParts = [city, region, country]
      .filter(Boolean)
      .join(", ") || "unknown";

    const location = timezone
      ? `${locationParts} (${timezone})`
      : locationParts;

    const asnNumber = asnObj.asn ? `AS${asnObj.asn}` : "";
    const asnName = asnObj.org || asnObj.name || company.name || "";
    const asnType = company.type || asnObj.type || "";
    const asnStr = [asnNumber, asnName]
      .filter(Boolean)
      .join(" ")
      .trim() || "unknown";

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
      cloudflare: {
        location: baseline.location,
        country: baseline.country,
        asn: baseline.asOrganization
          ? `AS${baseline.asn} ${baseline.asOrganization}`
          : baseline.asn,
      },
      verdict: {
        vpnLikely,
      },
    });

  } catch (e) {
    return json({
      ok: true,
      ...baseline,
      ipapi: { ok: false, error: "fetch_failed" },
      verdict: {
        vpnLikely: baseline.security.isAnonymousProxy,
        reason: "ipapi fetch failed",
      },
    });
  }
}
