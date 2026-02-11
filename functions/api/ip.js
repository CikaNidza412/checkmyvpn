export async function onRequest(context) {
  const req = context.request;

  // IP (iza Cloudflare-a radi pouzdano preko cf-connecting-ip)
  const ip =
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown";

  // Cloudflare geolokacija (radi kad je hostovano na Cloudflare)
  const cf = req.cf || {};
  const country = cf.country || "";
  const region = cf.region || "";
  const city = cf.city || "";
  const tz = cf.timezone || "";
  const asn = cf.asn ? `AS${cf.asn}` : "";
  const org = cf.asOrganization || "";

  const locationParts = [city, region, country].filter(Boolean).join(", ") || "unknown";
  const location = tz ? `${locationParts} (${tz})` : locationParts;

  // Ovo je samo "hint", nije prava VPN detekcija
  const vpnHint = cf.isAnonymousProxy ? "Mogući proxy/VPN (anonymous proxy)" : "Nema jasnog signala";

  const body = {
    ip,
    location,
    asn: [asn, org].filter(Boolean).join(" ") || "unknown",
    vpnHint
  };

  return new Response(JSON.stringify(body), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}
