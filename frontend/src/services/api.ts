const API_BASE_URL = "https://threatlens-vb1k49ku.back4.app";

export type Vulnerability = {
  id: string;
  description: string;
  severity: string;
  score: number | null;
  published: string | null;
  weaknesses: string[];
};

export type VulnerabilityDetails = Vulnerability & {
  cvss_version: string | null;
  last_modified: string | null;
  status: string | null;
  references: string[];
};

type VulnerabilitySearchResponse = {
  query: string;
  count: number;
  vulnerabilities: Vulnerability[];
};

export async function searchVulnerabilities(
  keyword: string,
  limit: number = 10
): Promise<VulnerabilitySearchResponse> {
  const params = new URLSearchParams({
    keyword,
    limit: String(limit),
  });

  const response = await fetch(
    `${API_BASE_URL}/api/vulnerabilities/search?${params}`
  );

  if (!response.ok) {
    throw new Error(`API request failed (${response.status})`);
  }

  return response.json();
}

export async function getVulnerabilityDetails(
  cveId: string
): Promise<VulnerabilityDetails> {
  const response = await fetch(
    `${API_BASE_URL}/api/vulnerabilities/${encodeURIComponent(cveId)}`
  );

  if (!response.ok) {
    const errorData = await response.json().catch(() => null);

    throw new Error(
      errorData?.detail || `Failed to fetch CVE details (${response.status})`
    );
  }

  return response.json();
}
