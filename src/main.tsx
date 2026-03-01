import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./ui/App";
import { initWebVitals } from "./monitoring/webVitals";
import "./ui/tokens.css";
import "./ui/styles.css";

initWebVitals();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
