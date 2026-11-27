
import { useCallback, useEffect, useState } from "react";

import Login from "./components/Login";
import UrlAnalyzer from "./components/UrlAnalyzer";
import FileAnalyzer from "./components/FileAnalyzer";
import AiExplanation from "./components/AiExplanation";
import ThreatIntelligence from "./components/ThreatIntelligence";

import {
  ShieldCheck,
  LayoutDashboard,
  MessageSquareText,
  Link2,
  FileSearch,
  Radar,
  History,
  Settings,
  Menu,
  X,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Server,
  LogOut,
  Search,
  LoaderCircle,
  RefreshCw,
  LockKeyhole,
  Clock3,
} from "lucide-react";

import {
  checkBackendHealth,
  getTotalScans,
  getAllScans,
  analyzeMessage,
  analyzeGuestMessage,
  clearCredentials,
  setUnauthorizedHandler,
} from "./services/api";

import "./App.css";

const navigation = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Message Scanner", icon: MessageSquareText },
  { name: "URL Analyzer", icon: Link2 },
  { name: "File Analyzer", icon: FileSearch },
  { name: "Threat Intelligence", icon: Radar },
  { name: "Scan History", icon: History },
  { name: "Settings", icon: Settings },
];

const guestPages = [
  "Message Scanner",
  "URL Analyzer",
  "File Analyzer",
];

function getRiskClass(level) {
  const value = String(level || "").toUpperCase();

  return ["LOW", "MEDIUM", "HIGH"].includes(value)
    ? `risk-${value.toLowerCase()}`
    : "risk-unknown";
}

function formatDate(value) {
  if (!value) return "N/A";

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? "N/A"
    : date.toLocaleString();
}

function MetricCard({
  title,
  value,
  icon: Icon,
  description,
}) {
  return (
    <div className="metric-card">
      <div className="metric-top">
        <span>{title}</span>
        <Icon size={21} />
      </div>

      <div className="metric-value">{value}</div>
      <p>{description}</p>
    </div>
  );
}

export default function App() {
  const [authenticated, setAuthenticated] =
    useState(false);

  const [isGuest, setIsGuest] = useState(false);
  const [sessionMessage, setSessionMessage] =
    useState("");

  const [activePage, setActivePage] =
    useState("Overview");

  const [sidebarOpen, setSidebarOpen] =
    useState(false);

  const [backendStatus, setBackendStatus] =
    useState("CHECKING");

  const [totalScans, setTotalScans] =
    useState(0);

  const [scanHistory, setScanHistory] =
    useState([]);

  const [scanDataError, setScanDataError] =
    useState("");

  const [message, setMessage] =
    useState("");

  const [result, setResult] =
    useState(null);

  const [analyzing, setAnalyzing] =
    useState(false);

  const [notice, setNotice] =
    useState("");

  const resetDashboard = useCallback(() => {
    setAuthenticated(false);
    setIsGuest(false);
    setActivePage("Overview");
    setSidebarOpen(false);
    setMessage("");
    setResult(null);
    setNotice("");
    setAnalyzing(false);
    setTotalScans(0);
    setScanHistory([]);
    setScanDataError("");
    setBackendStatus("CHECKING");
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearCredentials();
      resetDashboard();

      setSessionMessage(
        "Your login is no longer valid. Please sign in again."
      );
    });

    return () => setUnauthorizedHandler(null);
  }, [resetDashboard]);

  const refreshScans = useCallback(async () => {
    try {
      const [countData, historyData] =
        await Promise.all([
          getTotalScans(),
          getAllScans(),
        ]);

      setTotalScans(
        Number(countData.totalScans || 0)
      );

      setScanHistory(
        Array.isArray(historyData)
          ? historyData
          : []
      );

      setScanDataError("");
    } catch (error) {
      if (error.response?.status !== 401) {
        setScanDataError(
          "Unable to load scan history."
        );
      }
    }
  }, []);

  useEffect(() => {
    if (!authenticated && !isGuest) return;

    let cancelled = false;

    async function loadDashboard() {
      try {
        await checkBackendHealth();

        if (!cancelled) {
          setBackendStatus("ONLINE");
        }
      } catch {
        if (!cancelled) {
          setBackendStatus("OFFLINE");
        }
      }

      if (!cancelled && authenticated) {
        await refreshScans();
      }
    }

    loadDashboard();

    return () => {
      cancelled = true;
    };
  }, [authenticated, isGuest, refreshScans]);

  function handleLogin() {
    setIsGuest(false);
    setAuthenticated(true);
    setSessionMessage("");
    setActivePage("Overview");
    setResult(null);
    setNotice("");
  }

  function handleGuest() {
    clearCredentials();
    resetDashboard();
    setIsGuest(true);
    setSessionMessage("");
    setActivePage("Message Scanner");
  }

  function handleLogout() {
    clearCredentials();
    resetDashboard();
    setSessionMessage("");
  }

  function changePage(page) {
    if (isGuest && !guestPages.includes(page)) {
      return;
    }

    setActivePage(page);
    setSidebarOpen(false);
  }

  async function handleAnalyze(event) {
    event.preventDefault();

    if (analyzing) return;

    const cleanMessage = message.trim();
    const maxLength = isGuest ? 2000 : 10000;

    if (!cleanMessage) {
      setNotice(
        "Please enter a message to analyze."
      );
      return;
    }

    if (cleanMessage.length > maxLength) {
      setNotice(
        `Message must contain at most ${maxLength} characters.`
      );
      return;
    }

    setAnalyzing(true);
    setNotice("");
    setResult(null);

    try {
      const data = isGuest
        ? await analyzeGuestMessage(cleanMessage)
        : await analyzeMessage(cleanMessage);

      if (data?.status !== "COMPLETED") {
        throw new Error(
          "AI analysis was not completed."
        );
      }

      setResult(data);
      setNotice("Message analyzed successfully.");

      if (!isGuest) {
        await refreshScans();
      }
    } catch (error) {
      if (
        error.response?.status === 401 &&
        !isGuest
      ) {
        return;
      }

      if (error.response?.status === 429) {
        setNotice(
          "Guest scan limit reached. Please try again later."
        );
      } else if (error.response?.status === 503) {
        setNotice(
          "AI engine is temporarily unavailable."
        );
      } else {
        setNotice(
          error.response?.data?.message ||
            error.message ||
            "Message analysis failed."
        );
      }
    } finally {
      setAnalyzing(false);
    }
  }

  const detectedThreats = scanHistory.filter(
    (scan) =>
      scan.status === "COMPLETED" &&
      ["HIGH", "MEDIUM"].includes(
        String(scan.riskLevel || "").toUpperCase()
      )
  ).length;

  const completedScans = scanHistory.filter(
    (scan) => scan.status === "COMPLETED"
  ).length;

  const flaggedPercentage =
    completedScans > 0
      ? (
          (detectedThreats / completedScans) *
          100
        ).toFixed(1)
      : "0.0";

  const latestScan = scanHistory[0] || null;

  function renderScanTable(scans) {
    if (!scans.length) {
      return (
        <div className="empty-state">
          <History size={28} />
          <p>No scan records found.</p>
        </div>
      );
    }

    return (
      <div className="table-wrapper">
        <table className="scan-table">
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Type</th>
              <th>Risk Level</th>
              <th>Risk Score</th>
              <th>Status</th>
              <th>Date</th>
            </tr>
          </thead>

          <tbody>
            {scans.map((scan) => (
              <tr key={scan.id}>
                <td>#{scan.id}</td>
                <td>{scan.scanType || "N/A"}</td>
                <td>
                  <span
                    className={`risk-badge ${getRiskClass(
                      scan.riskLevel
                    )}`}
                  >
                    {scan.riskLevel || "UNKNOWN"}
                  </span>
                </td>
                <td>
                  {typeof scan.riskScore === "number"
                    ? `${scan.riskScore.toFixed(2)}%`
                    : "N/A"}
                </td>
                <td>{scan.status || "N/A"}</td>
                <td>{formatDate(scan.createdAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  function renderOverview() {
    return (
      <>
        <div className="page-heading">
          <div>
            <h1>Security Overview</h1>
            <p>
              Monitor your AI-powered security
              analysis activity.
            </p>
          </div>

          <button
            className="secondary-button"
            onClick={refreshScans}
          >
            <RefreshCw size={16} />
            Refresh
          </button>
        </div>

        <div className="metrics-grid">
          <MetricCard
            title="Total Scans"
            value={totalScans}
            icon={Activity}
            description="All recorded security scans"
          />

          <MetricCard
            title="Flagged Scans"
            value={detectedThreats}
            icon={AlertTriangle}
            description="Medium and high risk results"
          />

          <MetricCard
            title="Flagged Percentage"
            value={`${flaggedPercentage}%`}
            icon={ShieldCheck}
            description="Share of completed scans flagged"
          />

          <MetricCard
            title="Latest Scan"
            value={
              latestScan
                ? `#${latestScan.id}`
                : "N/A"
            }
            icon={Clock3}
            description="Most recent recorded scan"
          />
        </div>

        {scanDataError && (
          <div className="alert-message">
            {scanDataError}
          </div>
        )}

        <div className="content-grid">
          <div className="panel">
            <div className="panel-heading">
              <h2>Quick Actions</h2>
              <p>Start a new security analysis.</p>
            </div>

            <div className="quick-actions">
              <button
                className="action-card"
                onClick={() =>
                  changePage("Message Scanner")
                }
              >
                <MessageSquareText size={24} />
                <strong>Scan Message</strong>
                <span>Analyze suspicious text</span>
              </button>

              <button
                className="action-card"
                onClick={() =>
                  changePage("URL Analyzer")
                }
              >
                <Link2 size={24} />
                <strong>Analyze URL</strong>
                <span>URL detection module</span>
              </button>

              <button
                className="action-card"
                onClick={() =>
                  changePage("Scan History")
                }
              >
                <History size={24} />
                <strong>Scan History</strong>
                <span>Review previous results</span>
              </button>
            </div>
          </div>

          <div className="panel">
            <div className="panel-heading">
              <h2>System Status</h2>
              <p>Application services</p>
            </div>

            <div className="system-row">
              <span>
                <Server size={18} />
                Java Backend
              </span>

              <span
                className={
                  backendStatus === "ONLINE"
                    ? "status-online"
                    : "status-offline"
                }
              >
                {backendStatus}
              </span>
            </div>

            <div className="system-row">
              <span>
                <LockKeyhole size={18} />
                Authentication
              </span>
              <span className="status-online">
                AUTHENTICATED
              </span>
            </div>

            <div className="system-row">
              <span>
                <ShieldCheck size={18} />
                Security Mode
              </span>
              <span>Developer</span>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-heading">
            <h2>Recent Scans</h2>
            <p>Latest recorded analysis results</p>
          </div>

          {renderScanTable(scanHistory.slice(0, 5))}
        </div>

        <p className="disclaimer">
          AI detection results are experimental.
          Risk scores are not validated security
          probabilities.
        </p>
      </>
    );
  }

  function renderMessageScanner() {
    const riskScore = Number(
      result?.risk_score ?? 0
    );

    const confidence = Number(
      result?.confidence_score
    );

    const hasConfidence =
      result?.confidence_score != null &&
      Number.isFinite(confidence);

    const modelVersion =
      result?.model_version || "Unknown";

    const isDemoModel =
      modelVersion.startsWith("demo-");

    const messageIndicators =
      Array.isArray(result?.indicators)
        ? result.indicators.filter(
            (item) => typeof item === "string"
          )
        : [];

    const maxLength = isGuest ? 2000 : 10000;

    const hasSavedScan =
      Number.isSafeInteger(
        Number(result?.scan_id)
      ) &&
      Number(result?.scan_id) > 0;

    const guestToken =
      result?.guest_explanation_token;

    return (
      <>
        <div className="page-heading">
          <div>
            <h1>AI Message Scanner</h1>
            <p>
              Analyze messages for potentially
              suspicious patterns.
            </p>
          </div>
        </div>

        <div className="panel scanner-panel">
          <div className="panel-heading">
            <h2>Enter Message</h2>
            <p>
              Paste an email, SMS, or chat
              message for AI analysis.
            </p>
          </div>

          <form onSubmit={handleAnalyze}>
            <textarea
              className="message-input"
              placeholder="Example: Your account has been suspended. Click this link immediately..."
              value={message}
              onChange={(event) =>
                setMessage(event.target.value)
              }
              maxLength={maxLength}
              rows={8}
            />

            <div className="scanner-actions">
              <span className="character-count">
                {message.length} /{" "}
                {maxLength.toLocaleString()} characters
              </span>

              <button
                type="submit"
                className="primary-button"
                disabled={analyzing}
              >
                {analyzing ? (
                  <>
                    <LoaderCircle size={17} />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Search size={17} />
                    Analyze Message
                  </>
                )}
              </button>
            </div>
          </form>
        </div>

        {notice && (
          <div
            className={
              result
                ? "success-message"
                : "alert-message"
            }
            role="status"
          >
            {notice}
          </div>
        )}

        {result && (
          <div className="panel result-panel">
            <div className="result-heading">
              <div>
                <h2>AI Analysis Result</h2>
                <p>
                  {isGuest
                    ? "Guest scan · Not saved"
                    : `Scan #${result.scan_id ?? "N/A"}`}
                </p>
              </div>

              <span
                className={`risk-badge ${getRiskClass(
                  result.risk_level
                )}`}
              >
                {result.risk_level || "UNKNOWN"} RISK
              </span>
            </div>

            <div className="result-grid">
              <div className="result-stat">
                <span>Prediction</span>
                <strong>
                  {result.prediction || "UNKNOWN"}
                </strong>
              </div>

              <div className="result-stat">
                <span>Risk Level</span>
                <strong>
                  {result.risk_level || "N/A"}
                </strong>
              </div>

              <div className="result-stat">
                <span>Risk Score</span>
                <strong>
                  {riskScore.toFixed(2)}%
                </strong>
              </div>

              <div className="result-stat">
                <span>Model Confidence</span>
                <strong>
                  {hasConfidence
                    ? `${confidence.toFixed(2)}%`
                    : "N/A"}
                </strong>
              </div>

              <div className="result-stat">
                <span>Model Version</span>
                <strong>{modelVersion}</strong>
              </div>
            </div>

            <div className="risk-progress-heading">
              <span>Risk Score</span>
              <strong>
                {riskScore.toFixed(2)}%
              </strong>
            </div>

            <div className="risk-progress">
              <div
                className={`risk-progress-fill ${getRiskClass(
                  result.risk_level
                )}`}
                style={{
                  width: `${Math.max(
                    0,
                    Math.min(100, riskScore)
                  )}%`,
                }}
              />
            </div>

            <div className="explanation-box">
              <h3>Model Analysis Explanation</h3>
              <p>
                {result.explanation ||
                  "No explanation was provided."}
              </p>
            </div>

            <div
              className="explanation-box"
              style={{ marginTop: 18 }}
            >
              <h3>Detected Message Indicators</h3>

              {messageIndicators.length ? (
                <ul
                  style={{
                    paddingLeft: 22,
                    marginTop: 12,
                  }}
                >
                  {messageIndicators.map(
                    (indicator, index) => (
                      <li
                        key={`${indicator}-${index}`}
                        style={{ marginBottom: 8 }}
                      >
                        {indicator}
                      </li>
                    )
                  )}
                </ul>
              ) : (
                <p>
                  No rule-based message indicators
                  were reported.
                </p>
              )}
            </div>

            {isGuest && guestToken && (
              <AiExplanation
                key={guestToken}
                isGuest={true}
                guestToken={guestToken}
              />
            )}

            {!isGuest && hasSavedScan && (
              <AiExplanation
                key={result.scan_id}
                scanId={result.scan_id}
              />
            )}

            <p className="disclaimer">
              {isDemoModel
                ? "This demonstration classifier is experimental. Its scores are not verified security probabilities. Do not submit sensitive messages."
                : "This machine-learning classifier is experimental. Model confidence is not a verified probability of phishing or safety. Do not submit sensitive messages."}
            </p>
          </div>
        )}
      </>
    );
  }

  function renderScanHistory() {
    return (
      <>
        <div className="page-heading">
          <div>
            <h1>Scan History</h1>
            <p>
              View scans stored in Supabase PostgreSQL.
            </p>
          </div>

          <button
            className="secondary-button"
            onClick={refreshScans}
          >
            <RefreshCw size={16} />
            Refresh
          </button>
        </div>

        {scanDataError && (
          <div className="alert-message">
            {scanDataError}
          </div>
        )}

        <div className="panel">
          <div className="panel-heading">
            <h2>All Scans</h2>
            <p>
              {scanHistory.length} records loaded
            </p>
          </div>

          {renderScanTable(scanHistory)}
        </div>
      </>
    );
  }

  function renderSettings() {
    return (
      <>
        <div className="page-heading">
          <div>
            <h1>Settings</h1>
            <p>Developer account settings.</p>
          </div>
        </div>

        <div className="panel settings-panel">
          <h2>Account</h2>

          <div className="system-row">
            <span>Username</span>
            <strong>developer</strong>
          </div>

          <div className="system-row">
            <span>Authentication</span>
            <strong>HTTP Basic</strong>
          </div>

          <div className="system-row">
            <span>Backend</span>
            <strong>
              {import.meta.env.VITE_API_BASE_URL ||
                "http://localhost:8080/api"}
            </strong>
          </div>

          <button
            className="logout-settings-button"
            onClick={handleLogout}
          >
            <LogOut size={17} />
            Logout
          </button>
        </div>
      </>
    );
  }

  function renderPage() {
    if (isGuest && !guestPages.includes(activePage)) {
      return renderMessageScanner();
    }

    switch (activePage) {
      case "Overview":
        return renderOverview();

      case "Message Scanner":
        return renderMessageScanner();

      case "URL Analyzer":
        return (
          <UrlAnalyzer
            key={isGuest ? "guest-url" : "developer-url"}
            isGuest={isGuest}
            onScanComplete={
              isGuest ? undefined : refreshScans
            }
          />
        );

      case "File Analyzer":
        return (
          <FileAnalyzer
            key={isGuest ? "guest-file" : "developer-file"}
            isGuest={isGuest}
            onScanComplete={
              isGuest ? undefined : refreshScans
            }
          />
        );

      case "Threat Intelligence":
        return <ThreatIntelligence />;

      case "Scan History":
        return renderScanHistory();

      case "Settings":
        return renderSettings();

      default:
        return renderOverview();
    }
  }

  if (!authenticated && !isGuest) {
    return (
      <>
        {sessionMessage && (
          <div
            className="alert-message"
            role="alert"
            style={{
              position: "fixed",
              top: 16,
              left: "50%",
              transform: "translateX(-50%)",
              zIndex: 1000,
              width: "min(90%, 430px)",
              textAlign: "center",
            }}
          >
            {sessionMessage}
          </div>
        )}

        <Login
          onLogin={handleLogin}
          onGuest={handleGuest}
        />
      </>
    );
  }

  const visibleNavigation = isGuest
    ? navigation.filter((item) =>
        guestPages.includes(item.name)
      )
    : navigation;

  return (
    <div className="app-layout">
      {sidebarOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className={`sidebar ${
          sidebarOpen ? "sidebar-open" : ""
        }`}
      >
        <div className="sidebar-brand">
          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>

          <div>
            <h2>CyberShield AI</h2>
            <span>Threat Intelligence</span>
          </div>

          <button
            className="sidebar-close"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close sidebar"
          >
            <X size={20} />
          </button>
        </div>

        <div className="sidebar-section-label">
          MAIN MENU
        </div>

        <nav className="sidebar-navigation">
          {visibleNavigation.map((item) => {
            const Icon = item.icon;

            return (
              <button
                key={item.name}
                className={`nav-item ${
                  activePage === item.name
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  changePage(item.name)
                }
              >
                <Icon size={19} />
                <span>{item.name}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-security">
            <CheckCircle2 size={17} />

            <span>
              {isGuest
                ? "Guest Session"
                : "Authenticated Session"}
            </span>
          </div>

          <button
            className="sidebar-logout"
            onClick={handleLogout}
          >
            <LogOut size={18} />
            Logout
          </button>
        </div>
      </aside>

      <div className="main-layout">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="menu-button"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open menu"
            >
              <Menu size={23} />
            </button>

            <span className="topbar-title">
              CyberShield AI
            </span>
          </div>

          <div className="topbar-right">
            <span
              className={`backend-indicator ${
                backendStatus === "ONLINE"
                  ? "online"
                  : "offline"
              }`}
            >
              <span className="status-dot" />
              Backend {backendStatus}
            </span>

            <div className="user-avatar">
              {isGuest ? "G" : "D"}
            </div>

            <span className="user-name">
              {isGuest ? "Guest" : "developer"}
            </span>

            <button
              className="header-logout"
              onClick={handleLogout}
              title="Logout"
              aria-label="Logout"
            >
              <LogOut size={19} />
            </button>
          </div>
        </header>

        <main className="main-content">
          {renderPage()}
        </main>

        <footer className="app-footer">
          CyberShield AI - AI-Powered Cyber Threat
          Intelligence Platform
        </footer>
      </div>
    </div>
  );
}
