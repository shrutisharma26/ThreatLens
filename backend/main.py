
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx

from backend.services.nvd_service import search_vulnerabilities

app = FastAPI(
    title="ThreatLens API",
    description="AI-powered Cybersecurity Threat Intelligence Platform",
    version="0.2.0",
)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "Welcome to ThreatLens!",
        "status": "operational",
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ThreatLens API",
    }


@app.get("/api/vulnerabilities/search")
async def vulnerability_search(
    keyword: str = Query(..., min_length=2),
    limit: int = Query(10, ge=1, le=50),
):
    try:
        results = await search_vulnerabilities(keyword, limit)

        return {
            "query": keyword,
            "count": len(results),
            "vulnerabilities": results,
        }

    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"NVD API request failed: {str(exc)}",
        )


@app.get("/api/vulnerabilities/{cve_id}")
async def get_vulnerability_details(cve_id: str):
    """
    Retrieve detailed information about a specific CVE from NVD.
    Example: /api/vulnerabilities/CVE-2024-3094
    """

    cve_id = cve_id.upper().strip()

    if not cve_id.startswith("CVE-"):
        raise HTTPException(
            status_code=400,
            detail="Invalid CVE ID format. Expected format: CVE-YYYY-NNNN",
        )

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(
                NVD_API_URL,
                params={"cveId": cve_id},
            )

            response.raise_for_status()
            data = response.json()

    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"NVD API request failed: {str(exc)}",
        )

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        raise HTTPException(
            status_code=404,
            detail=f"{cve_id} was not found in the NVD database.",
        )

    cve = vulnerabilities[0].get("cve", {})

    descriptions = cve.get("descriptions", [])
    description = next(
        (
            item.get("value", "")
            for item in descriptions
            if item.get("lang") == "en"
        ),
        "No description available.",
    )

    metrics = cve.get("metrics", {})
    cvss_score = None
    severity = "UNKNOWN"
    cvss_version = None

    for metric_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(metric_key, [])

        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = (
                cvss_data.get("baseSeverity")
                or metric_list[0].get("baseSeverity")
                or "UNKNOWN"
            )
            cvss_version = cvss_data.get("version")
            break

    weaknesses = []

    for weakness in cve.get("weaknesses", []):
        for description_item in weakness.get("description", []):
            if description_item.get("lang") == "en":
                weaknesses.append(description_item.get("value"))

    references = [
        reference.get("url")
        for reference in cve.get("references", [])
        if reference.get("url")
    ]

    return {
        "id": cve.get("id", cve_id),
        "description": description,
        "severity": severity.upper(),
        "score": cvss_score,
        "cvss_version": cvss_version,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "weaknesses": weaknesses,
        "references": references,
    }
