// Optional local heuristic helper. The active detection path uses FastAPI via background.js.
class LocalPhishingHelper {
  static looksSuspiciousUrl(url) {
    const u = String(url || "").toLowerCase();
    const flags = ["@", "%", "secure-login", "verify", "account", "update"];
    return flags.some((f) => u.includes(f));
  }
}
