import React from "react";
import type { StatusValue } from "./packs/types";

type StatusTone = "good" | "warn" | "bad" | "inapplicable" | "unresolved";

/**
 * Colour is an amplifier here, never the carrier: the status word itself is
 * always rendered, so a badge stays readable without colour perception.
 *
 * Exhaustive over StatusValue by construction. Widening the union without
 * assigning a tone is a compile error, which is the point: an unmapped status
 * must not silently render as a neutral badge.
 */
const STATUS_TONE: Record<StatusValue, StatusTone> = {
  SUCCESS: "good",
  COMPLETED: "good",
  PASS: "good",
  BLOCKED: "warn",
  FAILED: "bad",
  NOT_APPLICABLE: "inapplicable",
  UNKNOWN: "unresolved",
};

type Props = {
  status: StatusValue;
  /** Plain-language qualifier shown beside the status word. */
  detail?: string;
};

export function StatusBadge({ status, detail }: Props) {
  return (
    <span className="status-badge" data-status={status} data-tone={STATUS_TONE[status]}>
      <span className="status-badge-word">{status}</span>
      {detail ? <span className="status-badge-detail">{detail}</span> : null}
    </span>
  );
}
