
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:8080/api",
  timeout: 40000,
});

let authHeader = null;
let onUnauthorized = null;

export function setCredentials(username, password) {
  const bytes = new TextEncoder().encode(`${username}:${password}`);

  const binary = Array.from(bytes, (byte) =>
    String.fromCharCode(byte)
  ).join("");

  authHeader = `Basic ${btoa(binary)}`;
}

export function clearCredentials() {
  authHeader = null;
}

export function setUnauthorizedHandler(handler) {
  onUnauthorized = handler;
}

api.interceptors.request.use((config) => {
  if (authHeader) {
    config.headers.Authorization = authHeader;
  }

  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const isLoginRequest = error.config?.skipAuthRedirect;

    if (status === 401 && !isLoginRequest && authHeader) {
      clearCredentials();

      if (onUnauthorized) {
        onUnauthorized();
      }
    }

    return Promise.reject(error);
  }
);

export async function login(username, password) {
  setCredentials(username, password);

  try {
    await api.get("/scans/count", {
      skipAuthRedirect: true,
    });

    return true;
  } catch (error) {
    clearCredentials();
    throw error;
  }
}

export async function checkBackendHealth() {
  return (await api.get("/health")).data;
}

export async function getTotalScans() {
  return (await api.get("/scans/count")).data;
}

export async function getAllScans() {
  return (await api.get("/scans")).data;
}

export async function analyzeMessage(message) {
  return (
    await api.post("/analyze/message", { message })
  ).data;
}

export async function analyzeUrl(url) {
  const response = await api.post("/analyze/url", {
    url,
  });

  return response.data;
}

export async function analyzeFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await api.post(
    "/analyze/file",
    formData,
    {
      timeout: 60000,
    }
  );

  return response.data;
}

export async function getThreatIntelligenceSummary() {
  const response = await api.get(
    "/threat-intelligence/summary"
  );

  return response.data;
}

export const generateAiExplanation = (scanId) => {
    return api.post(
        `/scans/${scanId}/explanation`,
        null,
        { timeout: 210000 }
    );
};

export default api;
