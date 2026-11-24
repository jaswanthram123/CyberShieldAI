import { useRef, useState } from "react";
import AiExplanation from "./AiExplanation";

import {
  Upload,
  FileSearch,
  FileText,
  ShieldCheck,
  AlertTriangle,
  Hash,
  LoaderCircle,
  CheckCircle,
  X,
  ShieldAlert,
  Copy,
  Check,
  BrainCircuit,
} from "lucide-react";

import { analyzeFile } from "../services/api";

const MAX_FILE_SIZE = 10 * 1024 * 1024;

// ---------------------------------------
// Helper Functions
// ---------------------------------------

function formatSize(bytes) {
  const size = Number(bytes) || 0;

  if (size < 1024) {
    return `${size} B`;
  }

  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(2)} KB`;
  }

  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

function formatScore(score) {
  const value = Number(score);

  if (!Number.isFinite(value)) {
    return "N/A";
  }

  return `${value.toFixed(2)}%`;
}

function getRiskColor(level) {
  if (level === "HIGH") return "#ef4444";
  if (level === "MEDIUM") return "#f59e0b";
  if (level === "LOW") return "#22c55e";

  return "#94a3b8";
}

// ---------------------------------------
// Reusable Score Card
// ---------------------------------------

function ScoreCard({ title, score, color, description }) {
  const numericScore = Number(score);
  const validScore = Number.isFinite(numericScore)
    ? numericScore
    : 0;

  const width = Math.max(0, Math.min(100, validScore));

  return (
    <div
      className="panel"
      style={{
        padding: 18,
        margin: 0,
      }}
    >
      <p style={{ opacity: 0.75, marginBottom: 8 }}>
        {title}
      </p>

      <h2 style={{ fontSize: 26, marginBottom: 12 }}>
        {formatScore(score)}
      </h2>

      <div
        style={{
          height: 9,
          width: "100%",
          background: "#334155",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${width}%`,
            height: "100%",
            backgroundColor: color,
            borderRadius: 10,
          }}
        />
      </div>

      {description && (
        <p
          style={{
            opacity: 0.7,
            fontSize: 13,
            marginTop: 12,
          }}
        >
          {description}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------
// Main File Analyzer Component
// ---------------------------------------

export default function FileAnalyzer({ onScanComplete }) {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const inputRef = useRef(null);

  // ---------------------------------------
  // File Selection
  // ---------------------------------------

  function handleFileChange(event) {
    const selected = event.target.files?.[0];

    setResult(null);
    setError("");
    setCopied(false);

    if (!selected) {
      setFile(null);
      return;
    }

    if (selected.size === 0) {
      setError("Empty files are not supported.");
      setFile(null);

      event.target.value = "";
      return;
    }

    if (selected.size > MAX_FILE_SIZE) {
      setError("Maximum file size is 10 MB.");
      setFile(null);

      event.target.value = "";
      return;
    }

    setFile(selected);
  }

  // ---------------------------------------
  // Remove File
  // ---------------------------------------

  function clearFile() {
    setFile(null);
    setResult(null);
    setError("");
    setCopied(false);

    if (inputRef.current) {
      inputRef.current.value = "";
    }
  }

  // ---------------------------------------
  // Analyze File
  // ---------------------------------------

  async function handleAnalyze() {
    if (!file || loading) return;

    setLoading(true);
    setError("");
    setResult(null);
    setCopied(false);

    try {
      const data = await analyzeFile(file);

      if (data.status !== "COMPLETED") {
        throw new Error(
          "File analysis was not completed."
        );
      }

      setResult(data);

      if (onScanComplete) {
        Promise.resolve()
          .then(() => onScanComplete())
          .catch(() => {});
      }
    } catch (err) {
      if (err.response?.status === 401) {
        return;
      }

      const detail = err.response?.data?.detail;
      const message = err.response?.data?.message;

      if (err.response?.status === 413) {
        setError("Maximum file size is 10 MB.");
      } else if (typeof detail === "string") {
        setError(detail);
      } else if (typeof message === "string") {
        setError(message);
      } else {
        setError(
          err.message || "File analysis failed."
        );
      }
    } finally {
      setLoading(false);
    }
  }

  // ---------------------------------------
  // Copy SHA-256 Hash
  // ---------------------------------------

  async function copyHash() {
    if (!result?.sha256) return;

    try {
      await navigator.clipboard.writeText(
        result.sha256
      );

      setCopied(true);
    } catch {
      setError("Unable to copy SHA-256 hash.");
    }
  }

  // ---------------------------------------
  // Result Values
  // ---------------------------------------

  const riskLevel = result?.risk_level || "UNKNOWN";

  const riskScore = Number(
    result?.risk_score ?? 0
  );

  const riskColor = getRiskColor(riskLevel);

  const hasAdvancedScore =
    result?.advanced_risk_score != null;

  const hasBasicScore =
    result?.basic_risk_score != null;

  const hasYara =
    result?.yara_status != null;

  const yaraMatches = Array.isArray(result?.yara_matches)
    ? result.yara_matches
    : [];

  const indicators = Array.isArray(result?.indicators)
    ? result.indicators
    : [];

  const advancedIndicators =
    Array.isArray(result?.advanced_indicators)
      ? result.advanced_indicators
      : [];

  // ---------------------------------------
  // Render UI
  // ---------------------------------------

  return (
    <div>
      {/* -----------------------------------
          Page Heading
      ----------------------------------- */}

      <div className="page-heading">
        <div>
          <h1>AI File Analyzer</h1>

          <p>
            Analyze files using static security checks,
            file signatures, PDF/ZIP inspection, and
            YARA pattern matching.
          </p>
        </div>
      </div>

      {/* -----------------------------------
          File Upload Panel
      ----------------------------------- */}

      <div className="panel scanner-panel">
        <div className="panel-heading">
          <h2>
            <Upload
              size={20}
              style={{
                display: "inline",
                marginRight: 8,
              }}
            />
            Upload File
          </h2>

          <p>
            Select a file for security analysis.
            Maximum size: 10 MB.
          </p>
        </div>

        <input
          ref={inputRef}
          type="file"
          onChange={handleFileChange}
          disabled={loading}
          style={{ display: "none" }}
        />

        <div
          className="file-dropzone"
          style={{
            border: "2px dashed #64748b",
            borderRadius: 14,
            padding: "35px 20px",
            textAlign: "center",
            marginBottom: 20,
          }}
        >
          <Upload
            size={40}
            style={{ marginBottom: 12 }}
          />

          <h3>Select a file to analyze</h3>

          <p style={{ margin: "12px 0" }}>
            Files are inspected without being executed.
          </p>

          <button
            type="button"
            className="primary-button"
            disabled={loading}
            onClick={() => inputRef.current?.click()}
          >
            <Upload size={17} />
            Choose File
          </button>
        </div>

        {/* Selected File */}

        {file && (
          <div
            className="selected-file"
            style={{
              padding: 16,
              border: "1px solid #64748b",
              borderRadius: 10,
              marginBottom: 20,
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
            }}
          >
            <div style={{ minWidth: 0 }}>
              <FileText
                size={20}
                style={{
                  display: "inline",
                  marginRight: 8,
                }}
              />

              <strong
                style={{
                  overflowWrap: "anywhere",
                }}
              >
                {file.name}
              </strong>

              <p style={{ marginTop: 6 }}>
                {formatSize(file.size)}
              </p>
            </div>

            <button
              type="button"
              onClick={clearFile}
              disabled={loading}
              aria-label="Remove selected file"
              style={{
                background: "transparent",
                border: "none",
                color: "inherit",
                cursor: "pointer",
              }}
            >
              <X size={20} />
            </button>
          </div>
        )}

        {/* Analyze Button */}

        <button
          type="button"
          className="primary-button"
          disabled={!file || loading}
          onClick={handleAnalyze}
        >
          {loading ? (
            <>
              <LoaderCircle size={17} />
              Analyzing File...
            </>
          ) : (
            <>
              <FileSearch size={17} />
              Analyze File
            </>
          )}
        </button>
      </div>

      {/* -----------------------------------
          Error Message
      ----------------------------------- */}

      {error && (
        <div className="alert-message" role="alert">
          <AlertTriangle
            size={18}
            style={{
              display: "inline",
              marginRight: 8,
            }}
          />
          {error}
        </div>
      )}

      {/* -----------------------------------
          Analysis Results
      ----------------------------------- */}

      {result && (
        <div className="panel result-panel">
          {/* Result Header */}

          <div className="result-heading">
            <div>
              <h2>
                <CheckCircle
                  size={21}
                  style={{
                    display: "inline",
                    marginRight: 8,
                  }}
                />
                File Analysis Result
              </h2>

              <p>
                Scan #{result.scan_id ?? "N/A"}
              </p>
            </div>

            <span
              className={`risk-badge risk-${riskLevel.toLowerCase()}`}
            >
              {riskLevel} RISK
            </span>
          </div>

          {/* Main Result Statistics */}

          <div className="result-grid">
            <div className="result-stat">
              <span>Risk Score</span>
              <strong>
                {formatScore(riskScore)}
              </strong>
            </div>

            <div className="result-stat">
              <span>Risk Level</span>
              <strong>{riskLevel}</strong>
            </div>

            <div className="result-stat">
              <span>Prediction</span>
              <strong>
                {result.prediction || "N/A"}
              </strong>
            </div>

            <div className="result-stat">
              <span>File Size</span>
              <strong>
                {formatSize(result.file_size)}
              </strong>
            </div>
          </div>

          {/* Main Risk Progress */}

          <div className="risk-progress-heading">
            <span>Overall Risk Score</span>
            <strong>
              {formatScore(riskScore)}
            </strong>
          </div>

          <div className="risk-progress">
            <div
              className="risk-progress-fill"
              style={{
                width: `${Math.max(
                  0,
                  Math.min(100, riskScore)
                )}%`,
                backgroundColor: riskColor,
              }}
            />
          </div>

          {/* --------------------------------
              Security Analysis Scores
          -------------------------------- */}

          {(hasBasicScore ||
            hasAdvancedScore ||
            hasYara) && (
            <div style={{ marginTop: 24 }}>
              <h3
                style={{
                  marginBottom: 16,
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                }}
              >
                <BrainCircuit size={20} />
                Security Analysis Breakdown
              </h3>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns:
                    "repeat(auto-fit, minmax(190px, 1fr))",
                  gap: 15,
                }}
              >
                {hasBasicScore && (
                  <ScoreCard
                    title="Basic Risk Score"
                    score={result.basic_risk_score}
                    color="#6366f1"
                    description="Filename, extension, and signature checks"
                  />
                )}

                {hasAdvancedScore && (
                  <ScoreCard
                    title="Advanced Risk Points"
                    score={result.advanced_risk_score}
                    color="#f59e0b"
                    description="Additional heuristic points from PDF and ZIP checks"
                  />
                )}

                {hasYara && (
                  <ScoreCard
                    title="YARA Severity Score"
                    score={result.yara_risk_score}
                    color="#ef4444"
                    description="Highest severity score among matched YARA rules"
                  />
                )}
              </div>
            </div>
          )}

          {/* --------------------------------
              File Information
          -------------------------------- */}

          <div
            className="explanation-box"
            style={{ marginTop: 20 }}
          >
            <h3>
              <FileText
                size={18}
                style={{
                  display: "inline",
                  marginRight: 8,
                }}
              />
              File Information
            </h3>

            <p>
              <strong>Filename:</strong>{" "}
              {result.filename || "N/A"}
            </p>

            <p>
              <strong>Extension:</strong>{" "}
              {result.file_extension || "N/A"}
            </p>

            <p>
              <strong>File Signature:</strong>{" "}
              {result.file_signature || "N/A"}
            </p>

            <p>
              <strong>Analysis Version:</strong>{" "}
              {result.model_version || "N/A"}
            </p>
          </div>

          {/* --------------------------------
              SHA-256 Hash
          -------------------------------- */}

          <div
            className="explanation-box"
            style={{ marginTop: 18 }}
          >
            <h3>
              <Hash
                size={18}
                style={{
                  display: "inline",
                  marginRight: 8,
                }}
              />
              SHA-256 File Hash
            </h3>

            <code
              style={{
                overflowWrap: "anywhere",
                display: "block",
                marginTop: 12,
              }}
            >
              {result.sha256 || "N/A"}
            </code>

            {result.sha256 && (
              <button
                type="button"
                onClick={copyHash}
                style={{
                  marginTop: 12,
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                }}
              >
                {copied ? (
                  <>
                    <Check size={16} />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy size={16} />
                    Copy Hash
                  </>
                )}
              </button>
            )}
          </div>

          {/* --------------------------------
              All Detected Indicators
          -------------------------------- */}

          <div
            className="explanation-box"
            style={{ marginTop: 18 }}
          >
            <h3>
              <AlertTriangle
                size={18}
                style={{
                  display: "inline",
                  marginRight: 8,
                }}
              />
              Detected Security Indicators
            </h3>

            {indicators.length > 0 ? (
              <ul
                style={{
                  paddingLeft: 22,
                  marginTop: 12,
                }}
              >
                {indicators.map((indicator, index) => (
                  <li
                    key={index}
                    style={{ marginBottom: 10 }}
                  >
                    {indicator}
                  </li>
                ))}
              </ul>
            ) : (
              <p>
                No security indicators detected
                by the current rules.
              </p>
            )}
          </div>

          {/* --------------------------------
              Advanced Indicators
          -------------------------------- */}

          {result.advanced_indicators != null && (
            <div
              className="explanation-box"
              style={{ marginTop: 18 }}
            >
              <h3>
                <FileSearch
                  size={18}
                  style={{
                    display: "inline",
                    marginRight: 8,
                  }}
                />
                Advanced File Inspection
              </h3>

              {advancedIndicators.length > 0 ? (
                <ul
                  style={{
                    paddingLeft: 22,
                    marginTop: 12,
                  }}
                >
                  {advancedIndicators.map(
                    (indicator, index) => (
                      <li
                        key={index}
                        style={{ marginBottom: 10 }}
                      >
                        {indicator}
                      </li>
                    )
                  )}
                </ul>
              ) : (
                <p>
                  No additional PDF or ZIP
                  indicators detected.
                </p>
              )}
            </div>
          )}

          {/* --------------------------------
              YARA Signature Analysis
          -------------------------------- */}

          {hasYara && (
            <div
              className="explanation-box"
              style={{ marginTop: 18 }}
            >
              <h3>
                <ShieldAlert
                  size={19}
                  style={{
                    display: "inline",
                    marginRight: 8,
                  }}
                />
                YARA Signature Analysis
              </h3>

              <p>
                <strong>Status:</strong>{" "}
                {result.yara_status}
              </p>

              <p>
                <strong>Matched Rules:</strong>{" "}
                {yaraMatches.length}
              </p>

              <p>
                <strong>YARA Severity Score:</strong>{" "}
                {formatScore(result.yara_risk_score)}
              </p>

              {yaraMatches.length > 0 ? (
                <ul
                  style={{
                    paddingLeft: 22,
                    marginTop: 16,
                  }}
                >
                  {yaraMatches.map((match, index) => (
                    <li
                      key={`${match.rule}-${index}`}
                      style={{
                        marginBottom: 18,
                      }}
                    >
                      <strong>
                        {match.rule}
                      </strong>

                      <p
                        style={{
                          marginTop: 6,
                        }}
                      >
                        {match.description}
                      </p>

                      <p>
                        <strong>Severity:</strong>{" "}
                        {String(
                          match.severity || "unknown"
                        ).toUpperCase()}
                      </p>

                      <p>
                        <strong>Rule Score:</strong>{" "}
                        {match.score ?? "N/A"}
                      </p>
                    </li>
                  ))}
                </ul>
              ) : (
                <p style={{ marginTop: 12 }}>
                  {result.yara_status === "COMPLETED"
                    ? "No YARA signatures matched."
                    : "YARA did not return completed scan results."}
                </p>
              )}

              {result.yara_error && (
                <p
                  role="alert"
                  style={{
                    marginTop: 12,
                    color: "#ef4444",
                  }}
                >
                  YARA Error: {result.yara_error}
                </p>
              )}
            </div>
          )}

          {/* --------------------------------
              Analysis Warning
          -------------------------------- */}

          {result.analysis_warning && (
            <div
              className="explanation-box"
              role="alert"
              style={{
                marginTop: 18,
                border: "1px solid #f59e0b",
              }}
            >
              <h3>
                <AlertTriangle
                  size={18}
                  style={{
                    display: "inline",
                    marginRight: 8,
                    color: "#f59e0b",
                  }}
                />
                Analysis Warning
              </h3>

              <p>{result.analysis_warning}</p>
            </div>
          )}

          {/* --------------------------------
              Analysis Explanation
          -------------------------------- */}

          <div
            className="explanation-box"
            style={{ marginTop: 18 }}
          >
            <h3>
              <BrainCircuit
                size={18}
                style={{
                  display: "inline",
                  marginRight: 8,
                }}
              />
              Analysis Explanation
            </h3>

            <p>
              {result.explanation ||
                "No explanation available."}
            </p>
          </div>

          {/* --------------------------------
              Security Disclaimer
          -------------------------------- */}

          <div
            className="explanation-box"
            style={{ marginTop: 18 }}
          >
            <ShieldCheck
              size={19}
              style={{
                display: "inline",
                marginRight: 8,
              }}
            />

            Static analysis only. Uploaded files
            are not executed. Detection rules
            and YARA matches identify suspicious
            patterns but cannot confirm malware.

            A LOW risk score does not guarantee
            that a file is safe.
          </div>

          {/* Explain the saved scan using stored findings. */}
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
