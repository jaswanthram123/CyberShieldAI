
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

import {
  analyzeFile,
  analyzeGuestFile,
} from "../services/api";

const DEVELOPER_MAX_SIZE = 10 * 1024 * 1024;
const GUEST_MAX_SIZE = 2 * 1024 * 1024;

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
  if (score == null) return "N/A";

  const value = Number(score);

  return Number.isFinite(value)
    ? `${value.toFixed(2)}%`
    : "N/A";
}

function getRiskColor(level) {
  if (level === "HIGH") return "#ef4444";
  if (level === "MEDIUM") return "#f59e0b";
  if (level === "LOW") return "#22c55e";

  return "#94a3b8";
}

function ScoreCard({
  title,
  score,
  color,
  description,
}) {
  const numericScore = Number(score);

  const width = Number.isFinite(numericScore)
    ? Math.max(0, Math.min(100, numericScore))
    : 0;

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

function IndicatorList({
  indicators,
  emptyMessage,
}) {
  if (
    !Array.isArray(indicators) ||
    indicators.length === 0
  ) {
    return <p>{emptyMessage}</p>;
  }

  return (
    <ul style={{ paddingLeft: 22, marginTop: 12 }}>
      {indicators.map((indicator, index) => (
        <li key={index} style={{ marginBottom: 10 }}>
          {String(indicator)}
        </li>
      ))}
    </ul>
  );
}

export default function FileAnalyzer({
  onScanComplete,
  isGuest = false,
}) {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const inputRef = useRef(null);

  const maxFileSize = isGuest
    ? GUEST_MAX_SIZE
    : DEVELOPER_MAX_SIZE;

  const maxFileSizeLabel =
    isGuest ? "2 MB" : "10 MB";

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

    if (selected.size > maxFileSize) {
      setError(
        `Maximum file size is ${maxFileSizeLabel}.`
      );
      setFile(null);
      event.target.value = "";
      return;
    }

    setFile(selected);
  }

  function clearFile() {
    setFile(null);
    setResult(null);
    setError("");
    setCopied(false);

    if (inputRef.current) {
      inputRef.current.value = "";
    }
  }

  async function handleAnalyze() {
    if (!file || loading) return;

    if (file.size > maxFileSize) {
      setError(
        `Maximum file size is ${maxFileSizeLabel}.`
      );
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    setCopied(false);

    try {
      const data = isGuest
        ? await analyzeGuestFile(file)
        : await analyzeFile(file);

      if (data?.status !== "COMPLETED") {
        throw new Error(
          "File analysis was not completed."
        );
      }

      setResult(data);

      if (!isGuest && onScanComplete) {
        Promise.resolve(onScanComplete()).catch(
          () => {}
        );
      }
    } catch (err) {
      if (
        err.response?.status === 401 &&
        !isGuest
      ) {
        return;
      }

      const detail = err.response?.data?.detail;
      const serverMessage =
        err.response?.data?.message;

      if (err.response?.status === 413) {
        setError(
          `Maximum file size is ${maxFileSizeLabel}.`
        );
      } else if (err.response?.status === 429) {
        setError(
          "Guest scan limit reached. Please try again later."
        );
      } else if (typeof detail === "string") {
        setError(detail);
      } else if (
        typeof serverMessage === "string"
      ) {
        setError(serverMessage);
      } else {
        setError(
          err.message || "File analysis failed."
        );
      }
    } finally {
      setLoading(false);
    }
  }

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

  const riskLevel =
    result?.risk_level || "UNKNOWN";

  const riskScore =
    Number(result?.risk_score ?? 0);

  const riskColor =
    getRiskColor(riskLevel);

  const hasBasicScore =
    result?.basic_risk_score != null;

  const hasAdvancedScore =
    result?.advanced_risk_score != null;

  const hasYara =
    result?.yara_status != null;

  const indicators =
    Array.isArray(result?.indicators)
      ? result.indicators
      : [];

  const advancedIndicators =
    Array.isArray(result?.advanced_indicators)
      ? result.advanced_indicators
      : [];

  const yaraMatches =
    Array.isArray(result?.yara_matches)
      ? result.yara_matches
      : [];

  const hasSavedScan =
    Number.isSafeInteger(Number(result?.scan_id)) &&
    Number(result?.scan_id) > 0;

  const guestToken =
    result?.guest_explanation_token;

  return (
    <div>
      <div className="page-heading">
        <div>
          <h1>AI File Analyzer</h1>

          <p>
            Analyze files using static security checks,
            file signatures, PDF/ZIP inspection,
            and YARA pattern matching.
          </p>
        </div>
      </div>

      {isGuest && (
        <div
          className="panel"
          style={{
            padding: 14,
            marginBottom: 18,
          }}
        >
          <ShieldCheck
            size={18}
            style={{
              display: "inline",
              marginRight: 8,
            }}
          />
          Guest Mode — Uploaded file results
          are not saved to scan history.
        </div>
      )}

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
            Maximum size: {maxFileSizeLabel}.
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
            onClick={() =>
              inputRef.current?.click()
            }
          >
            <Upload size={17} />
            Choose File
          </button>
        </div>

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

      {error && (
        <div
          className="alert-message"
          role="alert"
        >
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

      {result && (
        <div className="panel result-panel">
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
                {isGuest
                  ? "Guest scan · Not saved"
                  : `Scan #${result.scan_id ?? "N/A"}`}
              </p>
            </div>

            <span
              className={`risk-badge risk-${riskLevel.toLowerCase()}`}
            >
              {riskLevel} RISK
            </span>
          </div>

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
                    description="Additional PDF and ZIP heuristic findings"
                  />
                )}

                {hasYara && (
                  <ScoreCard
                    title="YARA Severity Score"
                    score={result.yara_risk_score}
                    color="#ef4444"
                    description="Highest severity among matched YARA rules"
                  />
                )}
              </div>
            </div>
          )}

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

            <IndicatorList
              indicators={indicators}
              emptyMessage="No security indicators detected by the current rules."
            />
          </div>

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

              <IndicatorList
                indicators={advancedIndicators}
                emptyMessage="No additional PDF or ZIP indicators detected."
              />
            </div>
          )}

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

              {yaraMatches.length ? (
                <ul
                  style={{
                    paddingLeft: 22,
                    marginTop: 16,
                  }}
                >
                  {yaraMatches.map((match, index) => (
                    <li
                      key={`${match.rule}-${index}`}
                      style={{ marginBottom: 18 }}
                    >
                      <strong>{match.rule}</strong>

                      <p style={{ marginTop: 6 }}>
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
                  }}
                />
                Analysis Warning
              </h3>

              <p>{result.analysis_warning}</p>
            </div>
          )}

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
        </div>
      )}
    </div>
  );
}
