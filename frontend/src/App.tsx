

import { useState, type FormEvent } from "react";

import "./App.css";

import {

  searchVulnerabilities,

  getVulnerabilityDetails,

  type Vulnerability,

  type VulnerabilityDetails,

} from "./services/api";

const GRAPH_POSITIONS = [

  { x: 18, y: 30 }, { x: 35, y: 20 }, { x: 72, y: 24 },

  { x: 82, y: 48 }, { x: 65, y: 72 }, { x: 38, y: 78 },

  { x: 20, y: 58 }, { x: 48, y: 42 }, { x: 88, y: 75 },

  { x: 12, y: 80 }, { x: 55, y: 15 }, { x: 75, y: 88 },

  { x: 30, y: 45 }, { x: 60, y: 55 }, { x: 42, y: 60 },

  { x: 90, y: 20 }, { x: 10, y: 40 }, { x: 50, y: 85 },

  { x: 70, y: 42 }, { x: 28, y: 15 },

];

const SEVERITY_FILTERS = [

  "ALL",

  "CRITICAL",

  "HIGH",

  "MEDIUM",

  "LOW",

  "UNKNOWN",

];

function getSeverityColor(severity: string): string {

  switch (severity.toUpperCase()) {

    case "CRITICAL": return "#e77869";

    case "HIGH": return "#f2b66d";

    case "MEDIUM": return "#e7d46f";

    case "LOW": return "#c9f77a";

    default: return "#9ba7b4";

  }

}

function App() {

  const [keyword, setKeyword] = useState("");

  const [searchHistory, setSearchHistory] = useState<string[]>(() => {

    try {

      const saved = localStorage.getItem("threatlens-search-history");

      return saved ? JSON.parse(saved) : [];

    } catch {

      return [];

    }

  });

  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);

  const [selectedSeverity, setSelectedSeverity] = useState("ALL");

  const [selectedCwe, setSelectedCwe] = useState("ALL");
  const [compareA, setCompareA] = useState("");
  const [compareB, setCompareB] = useState("");

  const comparisonA = vulnerabilities.find((v) => v.id === compareA);
  const comparisonB = vulnerabilities.find((v) => v.id === compareB);

  const comparisonRows = comparisonA && comparisonB
    ? [
        { label: "Severity", valueA: comparisonA.severity || "UNKNOWN", valueB: comparisonB.severity || "UNKNOWN" },
        { label: "CVSS Score", valueA: comparisonA.score ?? "N/A", valueB: comparisonB.score ?? "N/A" },
        { label: "Published", valueA: comparisonA.published ? new Date(comparisonA.published).toLocaleDateString() : "N/A", valueB: comparisonB.published ? new Date(comparisonB.published).toLocaleDateString() : "N/A" },
        { label: "Weaknesses (CWE)", valueA: comparisonA.weaknesses?.length ? comparisonA.weaknesses.join(", ") : "Not reported", valueB: comparisonB.weaknesses?.length ? comparisonB.weaknesses.join(", ") : "Not reported" },
        { label: "Description", valueA: comparisonA.description || "No description available", valueB: comparisonB.description || "No description available" },
      ]
    : [];

  const [bookmarks, setBookmarks] = useState<string[]>(() => {

    try {

      return JSON.parse(localStorage.getItem("threatlens-bookmarks") || "[]");

    } catch {

      return [];

    }

  });

  const [sortBy, setSortBy] = useState("score-desc");

  const [loading, setLoading] = useState(false);

  const [loadingMore, setLoadingMore] = useState(false);

  const [resultLimit, setResultLimit] = useState(20);

  const [error, setError] = useState("");

  const [selectedCve, setSelectedCve] =

    useState<VulnerabilityDetails | null>(null);

  const [detailsLoading, setDetailsLoading] = useState(false);

  const [copiedCveId, setCopiedCveId] = useState("");

  async function handleSearch(event: FormEvent<HTMLFormElement>) {

    event.preventDefault();

    if (keyword.trim().length < 2) {

      setError("Enter at least 2 characters.");

      return;

    }

    setLoading(true);

    setError("");

    setVulnerabilities([]);

    setSelectedSeverity("ALL");

    setSelectedCwe("ALL");

    setResultLimit(20);

    try {

      const searchTerm = keyword.trim();

      const result = await searchVulnerabilities(searchTerm, 20);

      setVulnerabilities(result.vulnerabilities);

      const updatedHistory = [

        searchTerm,

        ...searchHistory.filter(

          (item) => item.toLowerCase() !== searchTerm.toLowerCase()

        ),

      ].slice(0, 5);

      setSearchHistory(updatedHistory);

      localStorage.setItem(

        "threatlens-search-history",

        JSON.stringify(updatedHistory)

      );

    } catch (err) {

      setError(

        err instanceof Error

          ? err.message

          : "Failed to fetch vulnerability data."

      );

    } finally {

      setLoading(false);

    }

  }

  async function handleLoadMore() {

    if (loadingMore || loading || !keyword.trim()) return;

    const nextLimit = resultLimit + 20;

    setLoadingMore(true);

    setError("");

    try {

      const result = await searchVulnerabilities(keyword.trim(), nextLimit);

      setVulnerabilities(result.vulnerabilities);

      setResultLimit(nextLimit);

    } catch (err) {

      setError(

        err instanceof Error

          ? err.message

          : "Could not load more vulnerabilities."

      );

    } finally {

      setLoadingMore(false);

    }

  }

  function toggleBookmark(cveId: string) {

    const updated = bookmarks.includes(cveId)

      ? bookmarks.filter((id) => id !== cveId)

      : [...bookmarks, cveId];

    setBookmarks(updated);

    localStorage.setItem("threatlens-bookmarks", JSON.stringify(updated));

  }

  function handleExportCsv() {
    if (filteredVulnerabilities.length === 0) return;

    const columns = ["CVE ID", "Severity", "CVSS Score", "Published", "Description"];
    const escapeCsv = (value: string | number | null | undefined) => {
      const text = String(value ?? "");
      return `"${text.replace(/"/g, '""')}"`;
    };

    const rows = filteredVulnerabilities.map((vulnerability) => [
      vulnerability.id,
      vulnerability.severity,
      vulnerability.score ?? "",
      vulnerability.published ?? "",
      vulnerability.description,
    ]);

    const csv = [columns, ...rows]
      .map((row) => row.map(escapeCsv).join(","))
      .join("\r\n");

    const blob = new Blob(["\uFEFF", csv], {
      type: "text/csv;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `threatlens-${keyword.trim().replace(/[^a-z0-9_-]/gi, "_") || "vulnerabilities"}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function openCve(cveId: string) {

    setDetailsLoading(true);

    setSelectedCve(null);

    setError("");

    try {

      const details = await getVulnerabilityDetails(cveId);

      setSelectedCve(details);

    } catch (err) {

      setError(

        err instanceof Error

          ? err.message

          : "Could not load CVE details."

      );

    } finally {

      setDetailsLoading(false);

    }

  }

  // Overview metrics always use the complete search results.

  const criticalCount = vulnerabilities.filter(

    (v) => v.severity.toUpperCase() === "CRITICAL"

  ).length;

  const highCount = vulnerabilities.filter(

    (v) => v.severity.toUpperCase() === "HIGH"

  ).length;

  const severityBreakdown = [

    { label: "Critical", key: "CRITICAL", color: "#e77869" },

    { label: "High", key: "HIGH", color: "#f2b66d" },

    { label: "Medium", key: "MEDIUM", color: "#e7d46f" },

    { label: "Low", key: "LOW", color: "#c9f77a" },

    { label: "Unknown", key: "UNKNOWN", color: "#9ba7b4" },

  ].map((item) => ({

    ...item,

    count: vulnerabilities.filter(

      (v) => v.severity.toUpperCase() === item.key

    ).length,

  }));

  const averageScore =

    vulnerabilities.length > 0

      ? (

          vulnerabilities.reduce((sum, v) => sum + (v.score ?? 0), 0) /

          vulnerabilities.length

        ).toFixed(1)

      : "0.0";

  const criticalHighCount = criticalCount + highCount;
  const criticalHighPercent =
    vulnerabilities.length > 0
      ? Math.round((criticalHighCount / vulnerabilities.length) * 100)
      : 0;

  // CWE options are derived from the currently loaded NVD results.
  const availableCwes = Array.from(
    new Set(vulnerabilities.flatMap((v) => v.weaknesses ?? []))
  ).sort((a, b) => a.localeCompare(b));

  const cweCounts = availableCwes.map((cwe) => ({
    cwe,
    count: vulnerabilities.filter((v) => (v.weaknesses ?? []).includes(cwe)).length,
  })).sort((a, b) => b.count - a.count);
  const mostCommonCwe = cweCounts[0];

  // The selected severity affects the graph and feed only.

  const filteredVulnerabilities = vulnerabilities

    .filter((v) => {
      const matchesSeverity =
        selectedSeverity === "ALL" ||
        (selectedSeverity === "SAVED"
          ? bookmarks.includes(v.id)
          : v.severity.toUpperCase() === selectedSeverity);

      const matchesCwe =
        selectedCwe === "ALL" || (v.weaknesses ?? []).includes(selectedCwe);

      return matchesSeverity && matchesCwe;
    })

    .sort((a, b) => {

      if (sortBy === "score-desc") {

        return (b.score ?? -1) - (a.score ?? -1);

      }

      if (sortBy === "score-asc") {

        // Vulnerabilities without a score appear at the end.

        const scoreA = a.score ?? Number.POSITIVE_INFINITY;

        const scoreB = b.score ?? Number.POSITIVE_INFINITY;

        return scoreA - scoreB;

      }

      if (sortBy === "date-desc") {
        // Sort by the actual NVD publication timestamp, not the CVE ID year.
        // CVEs without a valid publication date stay at the bottom.
        const dateA = a.published ? Date.parse(a.published) : Number.NaN;
        const dateB = b.published ? Date.parse(b.published) : Number.NaN;
        const validA = Number.isFinite(dateA);
        const validB = Number.isFinite(dateB);

        if (!validA && !validB) return a.id.localeCompare(b.id);
        if (!validA) return 1;
        if (!validB) return -1;

        return dateB - dateA;
      }
      return a.id.localeCompare(b.id);

    });

  const graphNodes = filteredVulnerabilities.slice(

    0,

    GRAPH_POSITIONS.length

  );

  // Build graph edges only when two CVEs share an NVD-reported CWE.
  // These are weakness-category relationships, not proof of exploit chaining.
  const graphRelationships = graphNodes.flatMap((vulnerability, index) => {
    const vulnerabilityWeaknesses = vulnerability.weaknesses ?? [];

    return graphNodes.slice(index + 1).flatMap((other, offset) => {
      const sharedWeaknesses = vulnerabilityWeaknesses.filter((weakness) =>
        (other.weaknesses ?? []).includes(weakness)
      );

      if (sharedWeaknesses.length === 0) return [];

      return [{
        sourceIndex: index,
        targetIndex: index + 1 + offset,
        sharedWeaknesses,
      }];
    });
  });

  return (

    <div className="threat-app">

      <aside className="icon-rail">

        <div className="rail-logo">✦</div>

        <button className="rail-button active" title="Operations">◉</button>

        <button className="rail-button" title="Vulnerabilities">⌕</button>

        <button className="rail-button" title="Threat graph">⌘</button>

        <button className="rail-button" title="Reports">▤</button>

        <div className="rail-spacer" />

        <button className="rail-button" title="Settings">⚙</button>

        <div className="rail-avatar">S</div>

      </aside>

      <main className="command-main">

        <header className="command-topbar">

          <div className="topbar-left">

            <span className="breadcrumb">THREATLENS</span>

            <span className="breadcrumb-separator">/</span>

            <span className="breadcrumb-current">Operations</span>

          </div>

          <div className="topbar-right">

            <span className="system-status">

              <span className="pulse-dot" />

              SYSTEM ONLINE

            </span>

            <div className="top-avatar">S</div>

          </div>

        </header>

        <section className="command-heading">

          <div>

            <div className="heading-eyebrow">CYBER THREAT INTELLIGENCE</div>

            <h1>Operations Dashboard</h1>

            <p>Vulnerability monitoring and threat analysis.</p>

          </div>

          <form className="command-search" onSubmit={handleSearch}>

            <span>⌕</span>

            <input

              value={keyword}

              onChange={(e) => setKeyword(e.target.value)}

              placeholder="Search CVE, software, or vendor..."

            />

            <button type="submit" disabled={loading}>

              {loading ? "..." : "Search"}

            </button>

          </form>

          {searchHistory.length > 0 && (

            <div

              className="search-history"

              style={{

                display: "flex",

                alignItems: "center",

                flexWrap: "wrap",

                gap: "8px",

                marginTop: "12px",

              }}

            >

              <span

                style={{

                  color: "#829087",

                  fontSize: "10px",

                  letterSpacing: "1px",

                  marginRight: "3px",

                }}

              >

                RECENT SEARCHES

              </span>

              {searchHistory.map((term) => (

                <button

                  key={term}

                  type="button"

                  className="control-chip"

                  onClick={() => {

                    setKeyword(term);

                    setError("");

                    // Trigger the same search flow as submitting the search form.

                    void (async () => {

                      setLoading(true);

                      setVulnerabilities([]);

                      setSelectedSeverity("ALL");

                      setResultLimit(20);

                      try {

                        const result = await searchVulnerabilities(term, 20);

                        setVulnerabilities(result.vulnerabilities);

                      } catch (err) {

                        setError(

                          err instanceof Error

                            ? err.message

                            : "Failed to fetch vulnerability data."

                        );

                      } finally {

                        setLoading(false);

                      }

                    })();

                  }}

                >

                  ↺ {term}

                </button>

              ))}

              <button

                type="button"

                className="control-chip"

                onClick={() => {

                  setSearchHistory([]);

                  localStorage.removeItem("threatlens-search-history");

                }}

                title="Clear recent searches"

              >

                Clear history

              </button>

            </div>

          )}

        </section>

        <div className="control-strip">

          <div className="control-group">

            <button className="control-chip active-chip">◉ Overview</button>

            <button className="control-chip">Threat map</button>

            <button className="control-chip">Vulnerabilities</button>

            <button className="control-chip">Intelligence</button>

          </div>

          <div className="control-group">

            <span className="control-label">DATA SOURCE</span>

            <span className="source-chip">

              <span className="pulse-dot" /> NVD API

            </span>

          </div>

        </div>

        {error && <div className="command-error">{error}</div>}

        <section className="operations-layout">

          <div className="map-panel">

            <div className="map-grid" />

            <div className="map-glow" />

            <svg

              className="map-lines"

              viewBox="0 0 1000 600"

              preserveAspectRatio="none"

            >

              <path d="M30 90 L250 150 L360 90 L530 190 L720 100 L950 180" />

              <path d="M0 260 L170 230 L280 350 L450 280 L650 400 L900 330" />

              <path d="M80 500 L220 410 L400 480 L570 390 L780 500 L980 430" />

              <path d="M300 0 L350 180 L280 300 L360 600" />

              <path d="M700 0 L650 160 L780 270 L720 600" />

              <path d="M0 400 L200 370 L350 420 L500 350 L800 360 L1000 280" />

            </svg>

            <div className="map-road road-one" />

            <div className="map-road road-two" />

            <div className="map-road road-three" />

            <div className="map-road road-four" />

            <div className="map-header">

              <div>

                <span className="map-header-icon">⌁</span>

                <div>

                  <strong>THREAT RELATIONSHIP GRAPH</strong>

                  <small>

                    {vulnerabilities.length > 0

                      ? `${graphNodes.length} VISIBLE CVE NODES · ${graphRelationships.length} SHARED-CWE LINKS`

                      : "SEARCH TO LOAD VULNERABILITY NODES"}

                  </small>

                </div>

              </div>

              <span className="map-live">

                <span className="pulse-dot" /> LIVE

              </span>

            </div>

            {/* CWE-based graph connections */}
            <svg
              viewBox="0 0 100 100"
              preserveAspectRatio="none"
              style={{
                position: "absolute",
                inset: 0,
                width: "100%",
                height: "100%",
                zIndex: 2,
                overflow: "visible",
                pointerEvents: "none",
              }}
            >
              {graphRelationships.map((relationship) => {
                const source = GRAPH_POSITIONS[relationship.sourceIndex];
                const target = GRAPH_POSITIONS[relationship.targetIndex];

                return (
                  <line
                    key={`cwe-edge-${graphNodes[relationship.sourceIndex].id}-${graphNodes[relationship.targetIndex].id}`}
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    stroke="#d8f68a"
                    strokeOpacity={0.55}
                    strokeWidth={0.35}
                    strokeDasharray="1.2 0.8"
                  />
                );
              })}
              <circle
                cx="50"
                cy="50"
                r="4"
                fill="#d8f68a"
                fillOpacity="0.12"
                stroke="#d8f68a"
                strokeOpacity="0.7"
                strokeWidth="0.3"
              />
              <circle cx="50" cy="50" r="1.5" fill="#d8f68a" />
            </svg>

            {/* CVE nodes */}

            {graphNodes.map((vulnerability, index) => {

              const position = GRAPH_POSITIONS[index];

              const color = getSeverityColor(vulnerability.severity);

              return (

                <button

                  key={vulnerability.id}

                  title={`${vulnerability.id} · ${vulnerability.severity} · CWE: ${(vulnerability.weaknesses ?? []).join(", ") || "Not reported"} · Click for details`}

                  onClick={() => openCve(vulnerability.id)}

                  style={{

                    position: "absolute",

                    left: `${position.x}%`,

                    top: `${position.y}%`,

                    transform: "translate(-50%, -50%)",

                    zIndex: 5,

                    display: "flex",

                    alignItems: "center",

                    gap: "6px",

                    padding: "5px 7px",

                    color,

                    background: "#101412e8",

                    border: `1px solid ${color}75`,

                    borderRadius: "5px",

                    fontSize: "8px",

                    cursor: "pointer",

                    whiteSpace: "nowrap",

                    boxShadow: `0 0 12px ${color}18`,

                  }}

                >

                  <span

                    style={{

                      display: "inline-block",

                      width: "6px",

                      height: "6px",

                      borderRadius: "50%",

                      background: color,

                      boxShadow: `0 0 8px ${color}`,

                    }}

                  />

                  {vulnerability.id}

                </button>

              );

            })}

            {!loading && graphNodes.length === 0 && (

              <>

                <div className="map-node node-one">

                  <span />

                  <label>

                    {vulnerabilities.length > 0

                      ? "No matching severity"

                      : "Search for CVEs"}

                  </label>

                </div>

                <div className="map-node node-two">

                  <span />

                  <label>Threat intelligence</label>

                </div>

                <div className="map-node node-three">

                  <span />

                  <label>Vulnerability analysis</label>

                </div>

              </>

            )}

            {loading && (

              <div

                style={{

                  position: "absolute",

                  left: "50%",

                  top: "50%",

                  transform: "translate(-50%, -50%)",

                  zIndex: 8,

                  padding: "10px 15px",

                  color: "#d8f68a",

                  background: "#101412",

                  border: "1px solid #394332",

                  borderRadius: "6px",

                  fontSize: "11px",

                }}

              >

                Loading threat graph...

              </div>

            )}

            <div className="map-coordinate coordinate-one">CVE NETWORK</div>

            <div className="map-coordinate coordinate-two">NVD INTELLIGENCE</div>

            <div className="map-coordinate coordinate-three">THREAT CLUSTER</div>

            <div className="map-legend">

              <span><i className="legend-green" /> Low</span>

              <span><i className="legend-yellow" /> Medium</span>

              <span><i style={{ background: "#f2b66d" }} /> High</span>

              <span><i className="legend-red" /> Critical</span>

            </div>

            <div className="map-zoom">

              <button title="Zoom in">+</button>

              <button title="Zoom out">−</button>

              <button title="Center graph">⌖</button>

            </div>

            <div className="compass-widget">

              <span>N</span>

              <div className="compass-circle">

                <div className="compass-needle" />

              </div>

              <small>ORIENTATION</small>

            </div>

            <div className="map-footer">

              <span>THREATLENS INTELLIGENCE GRID</span>

              <span>Links indicate shared NVD-reported CWE categories; not exploit chains</span>

            </div>

          </div>

          <aside className="monitor-panel">

            <div className="monitor-card">

              <div className="monitor-card-heading">

                <span>THREAT OVERVIEW</span>

                <span className="tiny-menu">•••</span>

              </div>

              <div className="risk-row">

                <div>

                  <small>Average CVSS score</small>

                  <strong>{averageScore}<span>/10</span></strong>

                </div>

                <div className="risk-gauge">

                  <div className="gauge-inner">

                    <strong>{averageScore}</strong>

                    <small>RISK</small>

                  </div>

                </div>

              </div>

              <div className="risk-meter">

                <span style={{ width: `${Number(averageScore) * 10}%` }} />

              </div>

              <div className="monitor-meta">

                <span>CVSS average</span>

                <span>{vulnerabilities.length} records</span>

              </div>

            </div>

            <div className="monitor-card">

              <div className="monitor-card-heading">

                <span>VULNERABILITY STATUS</span>

                <span className="tiny-menu">•••</span>

              </div>

              <div className="mini-stat-row">

                <span>Critical findings</span>

                <strong className="text-red">{criticalCount}</strong>

              </div>

              <div className="mini-stat-row">

                <span>High severity</span>

                <strong className="text-orange">{highCount}</strong>

              </div>

              <div className="mini-stat-row">

                <span>Total findings</span>

                <strong>{vulnerabilities.length}</strong>

              </div>

            </div>

            <div className="monitor-card">

              <div className="monitor-card-heading">

                <span>SEVERITY DISTRIBUTION</span>

                <span className="tiny-menu">CVEs</span>

              </div>

              {severityBreakdown.map((item) => {

                const percentage =

                  vulnerabilities.length > 0

                    ? (item.count / vulnerabilities.length) * 100

                    : 0;

                return (

                  <button

                    key={item.key}

                    type="button"

                    onClick={() => setSelectedSeverity(item.key)}

                    title={`Filter to ${item.label} vulnerabilities`}

                    style={{

                      width: "100%",

                      display: "block",

                      textAlign: "left",

                      padding: "8px 0",

                      border: "none",

                      background: "transparent",

                      color: "#cbd4cb",

                      cursor: "pointer",

                    }}

                  >

                    <div

                      style={{

                        display: "flex",

                        justifyContent: "space-between",

                        alignItems: "center",

                        marginBottom: "5px",

                        fontSize: "11px",

                      }}

                    >

                      <span>

                        <span

                          style={{

                            display: "inline-block",

                            width: "7px",

                            height: "7px",

                            borderRadius: "50%",

                            background: item.color,

                            marginRight: "8px",

                          }}

                        />

                        {item.label}

                      </span>

                      <strong style={{ color: item.color }}>{item.count}</strong>

                    </div>

                    <div

                      style={{

                        height: "5px",

                        width: "100%",

                        borderRadius: "5px",

                        background: "#242c26",

                        overflow: "hidden",

                      }}

                    >

                      <div

                        style={{

                          height: "100%",

                          width: `${percentage}%`,

                          background: item.color,

                          borderRadius: "5px",

                          transition: "width 250ms ease",

                        }}

                      />

                    </div>

                  </button>

                );

              })}

              <div className="monitor-meta">

                <span>Click a severity to filter feed</span>

                <span>{vulnerabilities.length} total</span>

              </div>

            </div>

            <div className="monitor-card">
              <div className="monitor-card-heading">
                <span>RISK ANALYTICS</span>
                <span className="tiny-menu">SEARCH</span>
              </div>
              <div className="mini-stat-row">
                <span>Critical + High</span>
                <strong className="text-orange">{criticalHighPercent}%</strong>
              </div>
              <div style={{ height: "7px", background: "#242c26", borderRadius: "6px", overflow: "hidden", margin: "8px 0 12px" }}>
                <div style={{ height: "100%", width: `${criticalHighPercent}%`, background: "linear-gradient(90deg, #f2b66d, #e77869)", borderRadius: "6px" }} />
              </div>
              <div className="mini-stat-row">
                <span>Highest CVSS</span>
                <strong>{vulnerabilities.length ? Math.max(...vulnerabilities.map((v) => v.score ?? 0)).toFixed(1) : "—"}</strong>
              </div>
              <div className="mini-stat-row">
                <span>Most common CWE</span>
                <strong style={{ fontSize: "12px" }}>{mostCommonCwe ? mostCommonCwe.cwe : "N/A"}</strong>
              </div>
              {mostCommonCwe && (
                <div className="monitor-meta">
                  <span>Reported in</span>
                  <span>{mostCommonCwe.count} CVEs</span>
                </div>
              )}
              <small style={{ color: "#84918a", display: "block", marginTop: "8px", lineHeight: 1.4 }}>
                Metrics reflect loaded search results, not the entire NVD.
              </small>
            </div>

            <div className="monitor-card source-card">

              <div className="monitor-card-heading">

                <span>DATA SOURCE</span>

                <span className="source-connected">CONNECTED</span>

              </div>

              <div className="source-main">

                <div className="source-icon">◈</div>

                <div>

                  <strong>National Vulnerability Database</strong>

                  <small>NVD · CVE API 2.0</small>

                </div>

              </div>

              <div className="monitor-meta">

                <span>Connection</span>

                <span className="text-green">Operational</span>

              </div>

            </div>

          </aside>

        </section>

        {/* Severity filters */}

        <section className="bottom-section">

          <div className="bottom-heading">

            <div>

              <span className="heading-eyebrow">INTELLIGENCE FEED</span>

              <h2>Recent Vulnerabilities</h2>

            </div>

            <span className="result-count">

              {filteredVulnerabilities.length} / {vulnerabilities.length} RESULTS

            </span>

          </div>

          <div

            className="control-group"

            style={{

              marginBottom: "14px",

              display: "flex",

              alignItems: "center",

              flexWrap: "wrap",

              gap: "8px",

            }}

          >

            {SEVERITY_FILTERS.map((severity) => {

              const count =

                severity === "ALL"

                  ? vulnerabilities.length

                  : vulnerabilities.filter(

                      (v) => v.severity.toUpperCase() === severity

                    ).length;

              return (

                <button

                  key={severity}

                  className={`control-chip ${

                    selectedSeverity === severity ? "active-chip" : ""

                  }`}

                  onClick={() => setSelectedSeverity(severity)}

                >

                  {severity} ({count})

                </button>

              );

            })}

            <button

              type="button"

              className={`control-chip ${

                selectedSeverity === "SAVED" ? "active-chip" : ""

              }`}

              onClick={() => setSelectedSeverity("SAVED")}

            >

              ★ SAVED ({bookmarks.length})

            </button>

            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                color: "#9ba7a0",
                fontSize: "11px",
              }}
            >
              CWE
              <select
                value={selectedCwe}
                onChange={(event) => setSelectedCwe(event.target.value)}
                style={{
                  background: "#111713",
                  color: "#dce5dc",
                  border: "1px solid #344137",
                  borderRadius: "6px",
                  padding: "8px 10px",
                  fontSize: "11px",
                  maxWidth: "210px",
                }}
              >
                <option value="ALL">All weaknesses</option>
                {availableCwes.map((cwe) => (
                  <option key={cwe} value={cwe}>{cwe}</option>
                ))}
              </select>
            </label>

            <label

              style={{

                marginLeft: "auto",

                display: "flex",

                alignItems: "center",

                gap: "8px",

                color: "#9ba7a0",

                fontSize: "11px",

              }}

            >

              SORT BY

              <select

                value={sortBy}

                onChange={(event) => setSortBy(event.target.value)}

                style={{

                  background: "#111713",

                  color: "#dce5dc",

                  border: "1px solid #344137",

                  borderRadius: "6px",

                  padding: "8px 10px",

                  fontSize: "11px",

                }}

              >

                <option value="score-desc">CVSS: Highest first</option>

                <option value="score-asc">CVSS: Lowest first</option>

                <option value="date-desc">Published date: Newest first</option>

                <option value="id-asc">CVE ID: A–Z</option>

              </select>

            </label>

            <button
              type="button"
              className="control-chip"
              onClick={handleExportCsv}
              disabled={filteredVulnerabilities.length === 0}
              title="Export currently filtered vulnerabilities as CSV"
            >
              ↓ Export CSV
            </button>

            <label style={{ display: "flex", alignItems: "center", gap: "6px", color: "#9ba7a0", fontSize: "11px" }}>
              COMPARE
              <select value={compareA} onChange={(e) => setCompareA(e.target.value)} style={{ background: "#111713", color: "#dce5dc", border: "1px solid #344137", borderRadius: "6px", padding: "8px", maxWidth: "160px" }}>
                <option value="">Select CVE 1</option>
                {vulnerabilities.map((v) => <option key={v.id} value={v.id}>{v.id}</option>)}
              </select>
              <select value={compareB} onChange={(e) => setCompareB(e.target.value)} style={{ background: "#111713", color: "#dce5dc", border: "1px solid #344137", borderRadius: "6px", padding: "8px", maxWidth: "160px" }}>
                <option value="">Select CVE 2</option>
                {vulnerabilities.map((v) => <option key={v.id} value={v.id}>{v.id}</option>)}
              </select>
            </label>
            {compareA && compareB && compareA === compareB && <span style={{ color: "#f2b66d", fontSize: "11px" }}>Choose two different CVEs.</span>}

          </div>

          {comparisonA && comparisonB && compareA !== compareB && (
            <section className="monitor-card" style={{ margin: "0 0 18px", padding: "18px", border: "1px solid #394332", background: "#101713" }}>
              <div className="monitor-card-heading">
                <span>CVЕ COMPARISON</span>
                <button type="button" className="control-chip" onClick={() => { setCompareA(""); setCompareB(""); }}>Clear comparison</button>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", color: "#dce5dc" }}>
                  <thead><tr>
                    <th style={{ textAlign: "left", padding: "10px", color: "#829087" }}>ATTRIBUTE</th>
                    <th style={{ textAlign: "left", padding: "10px", color: "#d8f68a" }}>{comparisonA.id}</th>
                    <th style={{ textAlign: "left", padding: "10px", color: "#d8f68a" }}>{comparisonB.id}</th>
                  </tr></thead>
                  <tbody>
                    {comparisonRows.map((row) => (
                      <tr key={row.label} style={{ borderTop: "1px solid #28312b" }}>
                        <td style={{ padding: "10px", verticalAlign: "top", color: "#9ba7a0", minWidth: "130px" }}>{row.label}</td>
                        <td style={{ padding: "10px", verticalAlign: "top", maxWidth: "360px", whiteSpace: row.label === "Description" ? "normal" : "normal" }}>{row.valueA}</td>
                        <td style={{ padding: "10px", verticalAlign: "top", maxWidth: "360px" }}>{row.valueB}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {loading && <div className="feed-empty">Fetching NVD data...</div>}

          {!loading && vulnerabilities.length === 0 && (

            <div className="feed-empty">

              Search for a vendor or product above to load live vulnerability data.

            </div>

          )}

          {!loading &&

            vulnerabilities.length > 0 &&

            filteredVulnerabilities.length === 0 && (

              <div className="feed-empty">

                No {selectedSeverity.toLowerCase()} severity vulnerabilities

                found in this search. Try another filter.

              </div>

            )}

          {!loading && filteredVulnerabilities.length > 0 && (

            <div className="vulnerability-feed">

              {filteredVulnerabilities.slice(0, 6).map((vulnerability) => (

                <button

                  className="feed-item"

                  key={vulnerability.id}

                  onClick={() => openCve(vulnerability.id)}

                >

                  <div

                    className={`feed-severity ${vulnerability.severity.toLowerCase()}`}

                  />

                  <div className="feed-content">

                    <strong>{vulnerability.id}</strong>

                    <p>{vulnerability.description}</p>
                    <small style={{ color: "#829087", fontSize: "10px" }}>
                      Published: {vulnerability.published
                        ? new Date(vulnerability.published).toLocaleDateString()
                        : "Unknown"}
                    </small>

                  </div>

                  <div className="feed-score">

                    <span>{vulnerability.severity}</span>

                    <strong>{vulnerability.score ?? "N/A"}</strong>

                  </div>

                  <span className="feed-arrow">↗</span>

                </button>

              ))}

            </div>

          )}

          {!loading && vulnerabilities.length >= resultLimit && (

            <div

              style={{

                display: "flex",

                justifyContent: "center",

                marginTop: "18px",

              }}

            >

              <button

                type="button"

                className="control-chip"

                onClick={handleLoadMore}

                disabled={loadingMore}

                style={{

                  padding: "10px 18px",

                  opacity: loadingMore ? 0.65 : 1,

                  cursor: loadingMore ? "wait" : "pointer",

                }}

              >

                {loadingMore ? "Loading more CVEs..." : "＋ Load 20 more CVEs"}

              </button>

            </div>

          )}

        </section>

      </main>

      {(detailsLoading || selectedCve) && (

        <div className="detail-overlay" onClick={() => setSelectedCve(null)}>

          <div className="detail-modal" onClick={(e) => e.stopPropagation()}>

            <button

              className="detail-close"

              onClick={() => setSelectedCve(null)}

            >

              ×

            </button>

            {detailsLoading && <p>Loading CVE details...</p>}

            {selectedCve && (

              <>

                <span className="heading-eyebrow">

                  VULNERABILITY INTELLIGENCE

                </span>

                <h2>{selectedCve.id}</h2>

                <div className="detail-meta">

                  <span

                    className={`severity-badge ${selectedCve.severity.toLowerCase()}`}

                  >

                    {selectedCve.severity}

                  </span>

                  <strong>CVSS {selectedCve.score ?? "N/A"}</strong>

                </div>

                <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", margin: "12px 0" }}>

                  <button

                    type="button"

                    className="control-chip"

                    onClick={() => toggleBookmark(selectedCve.id)}

                  >

                    {bookmarks.includes(selectedCve.id)

                      ? "★ Remove from saved CVEs"

                      : "☆ Save CVE"}

                  </button>

                  <button

                    type="button"

                    className="control-chip"

                    onClick={async () => {

                      try {

                        await navigator.clipboard.writeText(selectedCve.id);

                        setCopiedCveId(selectedCve.id);

                      } catch {

                        setError("Clipboard access was blocked. You can copy the CVE ID manually.");

                      }

                    }}

                  >

                    {copiedCveId === selectedCve.id ? "✓ CVE ID copied" : "⧉ Copy CVE ID"}

                  </button>

                  <a

                    className="control-chip"

                    href={`https://nvd.nist.gov/vuln/detail/${selectedCve.id}`}

                    target="_blank"

                    rel="noreferrer"

                    style={{ textDecoration: "none", display: "inline-flex", alignItems: "center" }}

                  >

                    Open in NVD ↗

                  </a>

                </div>

                <h3>Description</h3>

                <p>{selectedCve.description}</p>

                <h3>Details</h3>

                <p>Published: {selectedCve.published ?? "Unknown"}</p>

                <p>Status: {selectedCve.status ?? "Unknown"}</p>

                <h3>Weaknesses</h3>

                <p>

                  {selectedCve.weaknesses.join(", ") || "Not provided"}

                </p>

                <h3>References</h3>

                <ul>

                  {selectedCve.references.slice(0, 8).map((url) => (

                    <li key={url}>

                      <a href={url} target="_blank" rel="noreferrer">

                        {url}

                      </a>

                    </li>

                  ))}

                </ul>

              </>

            )}

          </div>

        </div>

      )}

    </div>

  );

}

export default App;
