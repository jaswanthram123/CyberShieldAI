import { useState } from "react";
import AiExplanation from "./AiExplanation";
import {
  Link2,
  Search,
  ShieldAlert,
  ShieldCheck,
  BrainCircuit,
  AlertTriangle,
  CheckCircle,
  LoaderCircle,
} from "lucide-react";

import { analyzeUrl } from "../services/api";

function ScoreCard({ title, score, color, description }) {
  const value = Number(score ?? 0);
  const safeScore = Number.isFinite(value)
    ? Math.max(0, Math.min(100, value))
    : 0;

  return (
    <div className="panel" style={{ padding: 20, margin: 0 }}>
      <p style={{ opacity: 0.7, marginBottom: 8 }}>
        {title}
      </p>

      <h2 style={{ fontSize: 30, marginBottom: 12 }}>
        {safeScore.toFixed(2)}%
      </h2>

      <div
        style={{
          width: "100%",
          height: 9,
          background: "#334155",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${safeScore}%`,
            height: "100%",
            background: color,
            borderRadius: 10,
          }}
        />
      </div>

      <p style={{ marginTop: 12, fontSize: 13, opacity: 0.7 }}>
        {description}
      </p>
    </div>
  );
}

export default function UrlAnalyzer({ onScanComplete }) {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleAnalyze(event) {
    event.preventDefault();

    if (loading) return;

    const trimmed = url.trim();

    if (!trimmed) {
      setError("Please enter a URL.");
      return;
    }

    if (!/^https?:\/\/\S+$/i.test(trimmed)) {
      setError("Enter a URL starting with http:// or https://");
      return;
    }

    if ((trimmed.match(/https?:\/\//gi) || []).length > 1) {
      setError("Please enter only one URL.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const data = await analyzeUrl(trimmed);
      setResult(data);

      if (onScanComplete) {
        Promise.resolve(onScanComplete()).catch(() => {});
      }
    } catch (err) {
      if (err.response?.status === 401) {
        return;
      }

      const detail = err.response?.data?.detail;
      const message = err.response?.data?.message;

      setError(
        typeof detail === "string"
          ? detail
          : typeof message === "string"
            ? message
            : "Unable to analyze the URL."
      );
    } finally {
      setLoading(false);
    }
  }

  const score = Number(result?.risk_score ?? 0);
  const level = result?.risk_level || "UNKNOWN";

  const riskColor =
    level === "HIGH"
      ? "#ef4444"
      : level === "MEDIUM"
        ? "#f59e0b"
        : level === "LOW"
          ? "#22c55e"
          : "#94a3b8";

  const hasML = result?.ml_risk_score != null;

  return (
    <div>
      <div className="page-heading">
        <h1>AI URL Analyzer</h1>

        <p>
          Detect suspicious URL patterns using machine
          learning and security rules.
        </p>
      </div>

      <div className="panel scanner-panel">
        <div className="panel-heading">
          <h2>
            <Link2
              size={20}
              style={{ display: "inline", marginRight: 8 }}
            />
            Analyze URL
          </h2>

          <p>Enter a website URL for security analysis.</p>
        </div>

        <form onSubmit={handleAnalyze}>
          <input
            type="text"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://example.com"
            maxLength={2048}
            disabled={loading}
            style={{
              width: "100%",
              padding: 14,
              borderRadius: 9,
              border: "1px solid #64748b",
              background: "transparent",
              color: "inherit",
              marginBottom: 18,
            }}
          />

          <button
            className="primary-button"
            type="submit"
            disabled={loading}
          >
            {loading ? (
              <>
                <LoaderCircle size={17} />
                Analyzing...
              </>
            ) : (
              <>
                <Search size={17} />
                Analyze URL
              </>
            )}
          </button>
        </form>
      </div>

      {error && (
        <div className="alert-message" role="alert">
          <AlertTriangle
            size={18}
            style={{ display: "inline", marginRight: 8 }}
          />
          {error}
        </div>
      )}

      {result && (
        <div className="panel result-panel">
          <div className="result-heading">
            <div>
              <h2>
                <CheckCircle
                  size={20}
                  style={{ display: "inline", marginRight: 8 }}
                />
                URL Analysis Result
              </h2>

              <p>Scan #{result.scan_id ?? "N/A"}</p>
            </div>

            <span
              className={`risk-badge risk-${level.toLowerCase()}`}
            >
              {level} RISK
            </span>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "repeat(auto-fit, minmax(220px, 1fr))",
              gap: 16,
              marginBottom: 22,
            }}
          >
            <ScoreCard
              title="Combined Risk Score"
              score={score}
              color={riskColor}
              description={
                hasML
                  ? "Provisional combined model and rule score"
                  : "Rule-based risk score"
              }
            />

            {hasML && (
              <>
                <ScoreCard
                  title="Heuristic Risk Score"
                  score={result.heuristic_risk_score}
                  color="#f59e0b"
                  description="Calculated using URL security rules"
                />

                <ScoreCard
                  title="Machine Learning Score"
                  score={result.ml_risk_score}
                  color="#6366f1"
                  description="Predicted phishing-class score"
                />
              </>
            )}
          </div>

          <div className="result-grid">
            <div className="result-stat">
              <span>Final Prediction</span>
              <strong>{result.prediction || "N/A"}</strong>
            </div>

            <div className="result-stat">
              <span>Risk Level</span>
              <strong>{level}</strong>
            </div>

            <div className="result-stat">
              <span>ML Prediction</span>
              <strong>
                {result.ml_prediction || "Not available"}
              </strong>
            </div>

            <div className="result-stat">
              <span>Model Version</span>
              <strong>{result.model_version || "N/A"}</strong>
            </div>
          </div>

          <div
            className="explanation-box"
            style={{ marginTop: 20 }}
          >
            <h3>
              <BrainCircuit
                size={19}
                style={{ display: "inline", marginRight: 8 }}
              />
              Analysis Explanation
            </h3>

            <p>{result.explanation}</p>
          </div>

          {Array.isArray(result.indicators) &&
            result.indicators.length > 0 && (
              <div
                className="explanation-box"
                style={{ marginTop: 20 }}
              >
                <h3>
                  <ShieldAlert
                    size={19}
                    style={{ display: "inline", marginRight: 8 }}
                  />
                  Detected Indicators
                </h3>

                <ul style={{ paddingLeft: 22, marginTop: 12 }}>
                  {result.indicators.map((item, index) => (
                    <li key={index} style={{ marginBottom: 8 }}>
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            )}

          <div className="explanation-box" style={{ marginTop: 20 }}>
            <ShieldCheck
              size={18}
              style={{ display: "inline", marginRight: 8 }}
            />
            This is a predictive security assessment.
            A LOW risk result does not guarantee
            that the website is safe.
          </div>

          {/* The explanation component reads stored findings by scan ID. */}
          {Number.isSafeInteger(Number(result.scan_id)) &&
            Number(result.scan_id) > 0 && (
              <AiExplanation
                key={result.scan_id}
                scanId={result.scan_id}
              />
            )}
        </div>
      )}
    </div>
  );
}
