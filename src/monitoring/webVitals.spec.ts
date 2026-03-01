import { beforeEach, describe, expect, it, vi } from "vitest";
import { initWebVitals } from "./webVitals";

const onCLS = vi.fn();
const onINP = vi.fn();
const onLCP = vi.fn();
const onTTFB = vi.fn();

vi.mock("web-vitals", () => ({
  onCLS: (cb: unknown) => onCLS(cb),
  onINP: (cb: unknown) => onINP(cb),
  onLCP: (cb: unknown) => onLCP(cb),
  onTTFB: (cb: unknown) => onTTFB(cb),
}));

describe("initWebVitals", () => {
  beforeEach(() => {
    onCLS.mockReset();
    onINP.mockReset();
    onLCP.mockReset();
    onTTFB.mockReset();
  });

  it("registers all metric callbacks", () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    initWebVitals();

    expect(onCLS).toHaveBeenCalledTimes(1);
    expect(onINP).toHaveBeenCalledTimes(1);
    expect(onLCP).toHaveBeenCalledTimes(1);
    expect(onTTFB).toHaveBeenCalledTimes(1);

    const report = onCLS.mock.calls[0][0] as (metric: {
      name: string;
      value: number;
      rating: string;
    }) => void;
    report({ name: "CLS", value: 0.02, rating: "good" });

    expect(consoleSpy).toHaveBeenCalledWith("[web-vitals]", "CLS", 0.02, "good");
    consoleSpy.mockRestore();
  });
});
