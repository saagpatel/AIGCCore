// codex-os-managed
const historicalStackMergeSubjects = new Set([
  "merge: update local execution integration base",
  "merge: refresh authority integrity prerequisite",
  "merge: refresh PR #76 atop landed stack",
]);

export default {
  extends: ["@commitlint/config-conventional"],
  ignores: [(message) => historicalStackMergeSubjects.has(message.trim())],
  rules: {
    "type-enum": [2, "always", ["feat", "fix", "refactor", "perf", "docs", "test", "build", "ci", "chore", "revert"]],
    "header-max-length": [2, "always", 72],
    "subject-empty": [2, "never"],
    "subject-full-stop": [2, "never", "."],
  },
};
