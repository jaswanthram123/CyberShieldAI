
import axios from "axios";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  "http://localhost:8080/api";

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 40000,
});

let authHeader = null;
let onUnauthorized = null;

// ========================================
// Developer Authentication
// ========================================

export function setCredentials(username, password) {
  const bytes = new TextEncoder().encode(
    `${username}:${password}`
  );

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

// ========================================
// Request Interceptor
// ========================================

api.interceptors.request.use((config) => {
  const path = config.url || "";

  const isGuestRequest =
    path.startsWith("/guest/");

  if (isGuestRequest) {
    // Never include developer credentials
    // in public guest requests.
    delete config.headers.Authorization;
  } else if (authHeader) {
    config.headers.Authorization = authHeader;
  }

  return config;
});

// ========================================
// Response Interceptor
// ========================================

api.interceptors.response.use(
  (response) => response,

  (error) => {
    const status = error.response?.status;
    const path = error.config?.url || "";

    const isGuestRequest =
      path.startsWith("/guest/");

    const skipAuthRedirect =
      error.config?.skipAuthRedirect === true;

    if (
      status === 401 &&
      !isGuestRequest &&
      !skipAuthRedirect &&
      authHeader
    ) {
      clearCredentials();

      if (typeof onUnauthorized === "function") {
        onUnauthorized();
      }
    }

    return Promise.reject(error);
  }
);

// ========================================
// Login
// ========================================

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

// ========================================
// Backend Health
// ========================================

export async function checkBackendHealth() {
  const response = await api.get("/health");

  return response.data;
}

// ========================================
// Developer Dashboard
// ========================================

export async function getTotalScans() {
  const response = await api.get("/scans/count");

  return response.data;
}

export async function getAllScans() {
  const response = await api.get("/scans");

  return response.data;
}

export async function getThreatIntelligenceSummary() {
  const response = await api.get(
    "/threat-intelligence/summary"
  );

  return response.data;
}

// ========================================
// Developer Message Scanner
// ========================================

export async function analyzeMessage(message) {
  const response = await api.post(
    "/analyze/message",
    { message }
  );

  return response.data;
}

// ========================================
// Developer URL Scanner
// ========================================

export async function analyzeUrl(url) {
  const response = await api.post(
    "/analyze/url",
    { url }
  );

  return response.data;
}

// ========================================
// Developer File Scanner
// ========================================

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

// ========================================
// Developer Gemini AI Explanation
// ========================================

export async function generateAiExplanation(scanId) {
  return api.post(
    `/scans/${scanId}/explanation`,
    null,
    {
      timeout: 210000,
    }
  );
}

// ========================================
// Guest Message Scanner
// ========================================

export async function analyzeGuestMessage(message) {
  const response = await api.post(
    "/guest/analyze/message",
    { message }
  );

  return response.data;
}

// ========================================
// Guest URL Scanner
// ========================================

export async function analyzeGuestUrl(url) {
  const response = await api.post(
    "/guest/analyze/url",
    { url }
  );

  return response.data;
}

// ========================================
// Guest File Scanner
// ========================================

export async function analyzeGuestFile(file) {
  const formData = new FormData();

  formData.append("file", file);

  const response = await api.post(
    "/guest/analyze/file",
    formData,
    {
      timeout: 60000,
    }
  );

  return response.data;
}

// ========================================
// Guest Gemini AI Explanation
// ========================================

export async function generateGuestAiExplanation(token) {
  const response = await api.post(
    "/guest/explain",
    { token },
    {
      timeout: 210000,
    }
  );

  return response.data;
}

export default api;
