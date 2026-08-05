import { describe, expect, it } from "vitest";
import type { PackCommandStatus } from "./ui/packs/types";

describe("ui smoke", () => {
  it("future pack status shape remains stable", () => {
    // "READY" used to sit here, but it is a RunState variant
    // (core/src/run/manager.rs:30), not a status any pack command emits.
    const status: PackCommandStatus = {
      status: "SUCCESS",
      message: "scaffold",
    };
    expect(status.status).toBe("SUCCESS");
    expect(status.message).toBe("scaffold");
  });
});
