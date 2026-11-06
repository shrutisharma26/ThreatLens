ThreatLens
ThreatLens is a cybersecurity threat intelligence dashboard for exploring, filtering, and comparing Common Vulnerabilities and Exposures (CVEs) using data from the NVD CVE API 2.0.

It combines a React + TypeScript frontend with a FastAPI backend to make vulnerability data easier to search and analyze.
Project status: Student portfolio project / local development. Risk metrics and graph relationships are calculated from the CVEs currently loaded in the dashboard. CWE-based graph edges indicate shared weakness categories—not confirmed exploit chains.

Features
- CVE search by keyword through the NVD API.
- Severity filtering for Critical, High, Medium, Low, Unknown, and all results.
- CVSS sorting from highest to lowest or lowest to highest.
- Publication-date sorting using the actual published timestamp.
- CVE details modal with CVSS, description, publication and modification dates, status, weaknesses, and references.
- CWE filtering based on weakness IDs reported by NVD.
- CVE comparison for examining two vulnerabilities side by side.
- Risk analytics for the currently loaded search results, including high/critical share and common weakness information.
- CVE graph visualization with relationships based on shared reported CWE IDs.
- Bookmarks saved in browser localStorage.
- Recent searches saved in browser localStorage.
- Load more results by increasing the requested result limit.
- CSV export of the currently filtered results.
- Quick CVE actions to save a CVE, copy its ID, and open its NVD page.