import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

const rootElement = document.getElementById("root");

if (!rootElement) {
  throw new Error("Không tìm thấy phần tử root để khởi chạy ứng dụng.");
}

createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
