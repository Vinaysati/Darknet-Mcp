export const INVESTIGATION_SOURCES = [
  "ransomware", "threatfox", "urlhaus", "otx", "stealer", "hibp", "intelx",
  "abuseipdb", "greynoise", "bazaar", "hybrid", "ransomlook", "tor", "onionlookup",
  "blockchain", "chainabuse", "vulners", "phishing", "pulsedive",
] as const;

export type InvestigationSource = (typeof INVESTIGATION_SOURCES)[number];
export type TargetType = "domain" | "email" | "ip" | "hash" | "url" | "onion" | "bitcoin" | "cve";
export type CheckStatus = "match" | "no_match" | "skipped" | "error" | "timeout" | "inconclusive";

export interface Indicator {
  type: "domain" | "ip" | "hash" | "url" | "onion" | "bitcoin" | "cve";
  value: string;
}

export interface InvestigationCheck {
  id: string;
  source: InvestigationSource;
  tool: string;
  status: CheckStatus;
  summary: string;
  match_count: number | null;
  evidence_ids: string[];
  started_at: string;
  finished_at: string;
  truncated: boolean;
  partial_results: boolean;
}

export interface InvestigationEvidence {
  id: string;
  source: InvestigationSource;
  tool: string;
  observed_at: string;
  source_url: string;
  original_event_at?: string;
  provenance: { kind: "untrusted_source_claim" | "local_configuration"; provider: string };
  data: unknown;
  indicators: Indicator[];
}

export interface InvestigationReport {
  schema_version: "1.0";
  target: { value: string; type: TargetType };
  started_at: string;
  finished_at: string;
  checks: InvestigationCheck[];
  evidence: InvestigationEvidence[];
  correlations: { indicator: Indicator; sources: InvestigationSource[]; evidence_ids: string[] }[];
  coverage: {
    selected: number;
    completed: number;
    matches: number;
    no_match: number;
    skipped: number;
    errors: number;
    timeouts: number;
    inconclusive: number;
    partial: boolean;
  };
  limitations: string[];
}
