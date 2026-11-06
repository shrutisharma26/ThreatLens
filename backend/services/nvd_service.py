import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def search_vulnerabilities(keyword: str, limit: int = 10):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            NVD_API_URL,
            params=params,
        )

        response.raise_for_status()
        data = response.json()

    vulnerabilities = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        # Extract English description
        descriptions = cve.get("descriptions", [])
        description = next(
            (
                d["value"]
                for d in descriptions
                if d.get("lang") == "en"
            ),
            "No description available",
        )

        # Extract CVSS severity and score
        metrics = cve.get("metrics", {})
        score = None
        severity = "Unknown"

        for metric_name in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            metric_list = metrics.get(metric_name, [])

            if metric_list:
                cvss = metric_list[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get(
                    "baseSeverity",
                    metric_list[0].get("baseSeverity", "Unknown"),
                )
                break

        # Extract reported CWE identifiers (e.g. CWE-79)
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            for weakness_description in weakness.get("description", []):
                if weakness_description.get("lang") == "en":
                    weakness_id = weakness_description.get("value")
                    if weakness_id and weakness_id not in weaknesses:
                        weaknesses.append(weakness_id)

        vulnerabilities.append({
            "id": cve.get("id"),
            "description": description,
            "severity": severity,
            "score": score,
            "published": cve.get("published"),
            "weaknesses": weaknesses,
        })

    return vulnerabilities
