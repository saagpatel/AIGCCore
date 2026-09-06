export function validateMainWindowConfig(config) {
  const windows = config?.app?.windows;
  if (!Array.isArray(windows)) {
    throw new Error("Tauri app.windows must define the desktop window list");
  }

  const mainWindows = windows.filter((window) => window?.label === "main");
  if (mainWindows.length !== 1) {
    throw new Error("Tauri config must define exactly one main window");
  }

  const mainWindow = mainWindows[0];
  for (const dimension of ["width", "height", "minWidth", "minHeight"]) {
    if (!Number.isFinite(mainWindow[dimension]) || mainWindow[dimension] <= 0) {
      throw new Error(`Main window ${dimension} must be a positive number`);
    }
  }
  if (mainWindow.minWidth > mainWindow.width || mainWindow.minHeight > mainWindow.height) {
    throw new Error("Main window minimum dimensions cannot exceed its initial size");
  }

  return mainWindow;
}
