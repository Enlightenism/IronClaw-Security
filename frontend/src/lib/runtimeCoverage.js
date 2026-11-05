export const COVERAGE_ENFORCE = "enforce";
export const COVERAGE_REPLACE = "replace";
export const COVERAGE_AUDIT = "audit";
export const COVERAGE_NONE = "none";

export const COVERAGE_LABELS = {
  [COVERAGE_ENFORCE]: "Enforce",
  [COVERAGE_REPLACE]: "Replace",
  [COVERAGE_AUDIT]: "Audit only",
  [COVERAGE_NONE]: "No return-path enforcement",
};

export const RUNTIME_GATE_RETURN = "return";
export const RUNTIME_GATE_INSTALL = "install";

// Mirrors the platform coverage matrix in skills/ironclaw-security/SKILL.md.
const coverage = (install, returnPath) => ({
  [RUNTIME_GATE_INSTALL]: install,
  [RUNTIME_GATE_RETURN]: returnPath,
});

export const RUNTIME_COVERAGE = {
  claude_code: coverage(COVERAGE_ENFORCE, COVERAGE_REPLACE),
  copilot: coverage(COVERAGE_ENFORCE, COVERAGE_REPLACE),
  gemini_cli: coverage(COVERAGE_ENFORCE, COVERAGE_ENFORCE),
  cursor: coverage(COVERAGE_ENFORCE, COVERAGE_AUDIT),
  goose: coverage(COVERAGE_ENFORCE, COVERAGE_NONE),
  hermes: coverage(COVERAGE_ENFORCE, COVERAGE_REPLACE),
  openclaw: coverage(COVERAGE_ENFORCE, COVERAGE_AUDIT),
};

export const getRuntimeCoverage = (program, gate) =>
  RUNTIME_COVERAGE[program]?.[gate] ?? COVERAGE_NONE;
