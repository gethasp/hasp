import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dataDir = path.dirname(fileURLToPath(import.meta.url));
const publicMatrixPath = path.join(dataDir, "comparison-matrix.public.json");
const privateMatrixPath = path.resolve(process.cwd(), "../../docs/competition/matrix.json");
const matrixPath = fs.existsSync(publicMatrixPath) ? publicMatrixPath : privateMatrixPath;
const matrix = JSON.parse(fs.readFileSync(matrixPath, "utf8"));

function rowByKey(rows, key) {
  return rows.find((row) => row.key === key);
}

function shortList(items, count = 2) {
  return (items || []).slice(0, count).map((item) => item.replace(/\.$/, ""));
}

const competitors = matrix.competitors.map((competitor) => ({
  ...competitor,
  competitor_edge_short: shortList(competitor.benefits_over_hasp, 2),
  weakness_short: shortList({
    "kontext-cli": [
      "The reviewed repo ships Claude support first; Cursor and Codex were still planned.",
      "Resolved secrets enter the agent process environment, and repo leak blocking is not the main product.",
    ],
    onecli: [
      "The model centers on HTTP gateway traffic, so local command and file-secret workflows stay outside the happy path.",
      "It needs a web/database control plane. That is useful for teams, heavier for a solo local repo.",
    ],
    fnox: [
      "The default developer path materializes secrets into env vars or shell state.",
      "The MCP surface can return raw secret values, and the reviewed repo scanner was still a placeholder.",
    ],
    "agent-vault": [
      "The product is still research preview, and the proxy/CA/container setup asks more from the operator.",
      "It is strongest for HTTP(S). Repo leak prevention and non-HTTP command/file delivery are weaker.",
    ],
    "tailscale-aperture": [
      "It is a managed beta tied to Tailscale identity and network assumptions.",
      "It does not give you a local vault, offline workflow, or repo leak guardrails.",
    ],
  }[competitor.id], 2),
}));

const haspExecutive = {
  name: matrix.hasp.name,
  license: "Source-available with FCL-1.0-ALv2",
  strong: [
    "Keeps local project secrets in an encrypted vault and releases them through scoped broker runs.",
    "Treats the repo as part of the risk: bindings, leak checks, redaction, and audited grants live in the same flow.",
  ],
  weak: [
    "No hosted team dashboard or central identity layer in V1.",
    "No HTTP gateway, provider catalog, or AI spend controls yet.",
  ],
};

const operatingCards = [
  {
    label: "Trust boundary",
    question: "Who has to be trusted during a run?",
    hasp: "Your machine. The local daemon owns vault access, grants, redaction, and audit.",
    alternatives: [
      "Kontext and Aperture put more authority in hosted services.",
      "OneCLI and Agent Vault route work through gateway or proxy stacks.",
    ],
    read: "Choose hosted control when the buyer needs one dashboard. Choose HASP when the repo-local path matters more.",
  },
  {
    label: "Secret visibility",
    question: "Can the agent read the secret value?",
    hasp: "Brokered runs resolve values at execution time and keep them out of agent-visible output.",
    alternatives: [
      "fnox and Kontext favor env injection.",
      "Agent Vault and Aperture hide provider keys behind HTTP forwarding.",
    ],
    read: "Env injection is easy to adopt. It also gives more processes a place to inspect the value.",
  },
  {
    label: "Approval",
    question: "Who decides when access is allowed?",
    hasp: "The operator grants once, for a session, or for a time window. Plaintext access stays separate.",
    alternatives: [
      "OneCLI and Aperture use gateway policy.",
      "Agent Vault uses proposals, service catalogs, and vault roles.",
    ],
    read: "Gateway policy works well for network traffic. HASP fits the moment when a local command needs one named secret.",
  },
  {
    label: "Repo safety",
    question: "What happens if a secret lands in the workspace?",
    hasp: "HASP scans, blocks managed-value leaks, redacts output, and records overrides.",
    alternatives: [
      "Most gateway products do not inspect the repo.",
      "fnox supports encrypted config, but the reviewed scanner was not implemented.",
    ],
    read: "This is the clearest HASP lane. The risk starts before an API call leaves the machine.",
  },
  {
    label: "Audit",
    question: "What evidence can the operator inspect later?",
    hasp: "Local audit covers grants, guardrails, capture, expose/hide, backup, and runtime events.",
    alternatives: [
      "Aperture and OneCLI give stronger central reporting.",
      "Agent Vault logs HTTP request metadata for proxied traffic.",
    ],
    read: "Central reporting helps security teams. Local audit helps a developer prove what happened in one repo.",
  },
  {
    label: "Setup weight",
    question: "How much machinery comes with the model?",
    hasp: "One binary, one vault file, and repo binding.",
    alternatives: [
      "Gateway tools often need a web service, database, proxy settings, or CA trust.",
      "Provider managers need account setup across each backend.",
    ],
    read: "More machinery can be worth it for teams. It is friction for a local agent workflow.",
  },
];

const featureMatrix = matrix.features.map((feature) => {
  const entries = competitors.map((competitor) => {
    const row = rowByKey(competitor.feature_rows || [], feature.key);
    return {
      competitor: competitor.name,
      value: row?.competitor || "Not reviewed",
      position: row?.position || "mixed",
      notes: row?.notes || "",
    };
  });
  const haspValue = competitors
    .map((competitor) => rowByKey(competitor.feature_rows || [], feature.key)?.hasp)
    .find(Boolean);

  return {
    ...feature,
    hasp: haspValue || "Reviewed",
    entries,
  };
});

export default {
  updated_at: matrix.updated_at,
  source_url: "https://github.com/gethasp/hasp/blob/main/docs/competition/matrix.json",
  hasp: matrix.hasp,
  haspExecutive,
  competitors,
  featureMatrix,
  operatingCards,
};
