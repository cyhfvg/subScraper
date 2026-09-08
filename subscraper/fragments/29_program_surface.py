"""Fragment 29_program_surface.py. Loaded into the main module namespace."""
def program_surface(program: Dict[str, Any], limit: int = 50) -> Dict[str, Any]:
    """
    Rank in-scope hosts by how much they look worth an agent's time.
    Every score carries the reasons that produced it so the agent can explain itself.
    """
    assets = collect_program_assets(program, {})
    ranked: List[Dict[str, Any]] = []

    for asset in assets:
        score = 0
        reasons: List[str] = []

        if asset["live"]:
            score += 5
            reasons.append("live host")
        status = asset.get("status_code")
        if status in (401, 403):
            score += 12
            reasons.append(f"auth-gated ({status})")
        elif status in (500, 502, 503):
            score += 8
            reasons.append(f"server error ({status})")
        elif status == 200:
            score += 3

        for severity, count in asset["severity_counts"].items():
            if count:
                score += SEVERITY_WEIGHT.get(severity, 1) * count
                reasons.append(f"{count} {severity} finding(s)")

        if asset["interesting"]:
            score += 20
            reasons.append("marked interesting")

        host_hits = [kw for kw in INTERESTING_HOST_KEYWORDS if kw in asset["host"].split(".")[0]]
        if host_hits:
            score += min(24, 8 * len(host_hits))
            reasons.append("hostname keywords: " + ", ".join(host_hits[:3]))

        tech_values = asset.get("tech") or []
        if isinstance(tech_values, str):
            tech_values = [tech_values]
        tech_blob = " ".join(str(t).lower() for t in tech_values)
        tech_hits = [kw for kw in INTERESTING_TECH_KEYWORDS if kw in tech_blob]
        if tech_hits:
            score += min(18, 6 * len(tech_hits))
            reasons.append("tech: " + ", ".join(tech_hits[:3]))

        title = (asset.get("title") or "").lower()
        if any(word in title for word in ("login", "sign in", "admin", "dashboard", "api", "swagger", "graphql")):
            score += 6
            reasons.append("interesting title")

        if score <= 0:
            continue
        ranked.append({
            "host": asset["host"],
            "root": asset["root"],
            "url": asset["url"],
            "status_code": status,
            "title": asset.get("title"),
            "tech": tech_values,
            "score": score,
            "reasons": reasons,
            "severity_counts": asset["severity_counts"],
        })

    ranked.sort(key=lambda item: (-item["score"], item["host"]))
    try:
        limit = max(1, min(1000, int(limit)))
    except (TypeError, ValueError):
        limit = 50
    return {"program_id": program["id"], "surface": ranked[:limit], "total_ranked": len(ranked)}
