import { beforeEach, describe, expect, it, vi } from "vitest";

const renderMock = vi.fn();
const createRootMock = vi.fn(() => ({ render: renderMock }));
const initWebVitalsMock = vi.fn();

vi.mock("react-dom/client", () => ({
  default: { createRoot: createRootMock },
  createRoot: createRootMock,
}));

vi.mock("./ui/App", () => ({
  App: () => null,
}));

vi.mock("./monitoring/webVitals", () => ({
  initWebVitals: initWebVitalsMock,
}));

describe("main entrypoint", () => {
  beforeEach(() => {
    document.body.innerHTML = '<div id="root"></div>';
    renderMock.mockReset();
    createRootMock.mockClear();
    initWebVitalsMock.mockClear();
    vi.resetModules();
  });

  it("initializes web vitals and renders the root app", async () => {
    await import("./main");

    expect(initWebVitalsMock).toHaveBeenCalledTimes(1);
    expect(createRootMock).toHaveBeenCalledWith(document.getElementById("root"));
    expect(renderMock).toHaveBeenCalledTimes(1);
  });
});
