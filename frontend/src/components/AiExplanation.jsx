
import { useState } from "react";

import {
  generateAiExplanation,
  generateGuestAiExplanation,
} from "../services/api";

// -----------------------------------------
// Identify the actual explanation model
// -----------------------------------------

function getModelLabel(model) {
  if (!model || typeof model !== "string") {
    return "Unknown explanation source";
  }

  const name = model.trim();
  const lower = name.toLowerCase();

  if (
    lower.includes("deterministic") ||
    lower.includes("fallback")
  ) {
    return "Predefined explanation";
  }

  if (lower.includes("gemini")) {
    return `Gemini AI (${name})`;
  }

  if (
    lower.startsWith("gemma") ||
    lower.includes("gemma3")
  ) {
    return `Gemma AI (${name})`;
  }

  if (lower.includes("llama")) {
    return `Llama AI (${name})`;
  }

  if (lower.includes("mistral")) {
    return `Mistral AI (${name})`;
  }

  return `AI Model (${name})`;
}

// -----------------------------------------
// AI Explanation Component
// -----------------------------------------

export default function AiExplanation({
  scanId,
  guestToken,
  isGuest = false,
}) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [guestTokenUsed, setGuestTokenUsed] =
    useState(false);

  const guestMode = isGuest === true;

  // -----------------------------------------
  // Generate Explanation
  // -----------------------------------------

  async function handleGenerate() {
    if (loading) return;

    if (guestMode) {
      if (!guestToken || guestTokenUsed) {
        setError(
          "This explanation request has expired or was already used. Please scan again."
        );
        return;
      }
    } else {
      const numericId = Number(scanId);

      if (
        !Number.isSafeInteger(numericId) ||
        numericId <= 0
      ) {
        setError("Invalid scan ID.");
        return;
      }
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      let data;

      if (guestMode) {
        // Guest explanation tokens are single-use.
        // Mark as used before sending the request
        // to prevent repeat clicks.
        setGuestTokenUsed(true);

        data = await generateGuestAiExplanation(
          guestToken
        );
      } else {
        const response =
          await generateAiExplanation(scanId);

        data = response.data;
      }

      if (data?.status !== "COMPLETED") {
        throw new Error(
          "AI explanation was not completed."
        );
      }

      setResult(data);
    } catch (err) {
      const status = err.response?.status;

      const serverMessage =
        err.response?.data?.message;

      if (guestMode && status === 429) {
        // The backend keeps the token when
        // the explanation limit is reached.
        setGuestTokenUsed(false);

        setError(
          "Guest AI explanation limit reached. Please try again later."
        );
      } else if (
        guestMode &&
        (status === 400 || status === 404)
      ) {
        setError(
          "The guest explanation token is invalid, expired, or already used. Please scan again."
        );
      } else if (status === 503) {
        setError(
          "AI explanation service is temporarily unavailable."
        );
      } else {
        setError(
          typeof serverMessage === "string"
            ? serverMessage
            : err.message ||
                "Unable to generate AI explanation."
        );
      }
    } finally {
      setLoading(false);
    }
  }

  // -----------------------------------------
  // Extract Explanation Sections
  // -----------------------------------------

  function getSection(name) {
    if (
      !result?.explanation ||
      typeof result.explanation !== "string"
    ) {
      return "";
    }

    const headings = [
      "Assessment:",
      "Reason:",
      "Recommendation:",
    ];

    const explanation = result.explanation;

    const start = explanation.indexOf(name);

    if (start === -1) {
      return "";
    }

    const contentStart = start + name.length;

    const nextPositions = headings
      .filter((heading) => heading !== name)
      .map((heading) =>
        explanation.indexOf(
          heading,
          contentStart
        )
      )
      .filter((position) => position !== -1);

    const end = nextPositions.length
      ? Math.min(...nextPositions)
      : explanation.length;

    return explanation
      .slice(contentStart, end)
      .trim();
  }

  const assessment = getSection("Assessment:");
  const reason = getSection("Reason:");
  const recommendation =
    getSection("Recommendation:");

  const hasStructuredSections =
    Boolean(assessment) ||
    Boolean(reason) ||
    Boolean(recommendation);

  // -----------------------------------------
  // Model Information
  // -----------------------------------------

  const modelName =
    typeof result?.model === "string"
      ? result.model
      : "";

  const modelLabel = getModelLabel(modelName);

  const canGenerate = guestMode
    ? Boolean(guestToken) &&
      !guestTokenUsed &&
      !result
    : true;

  const riskScore = Number(
    result?.risk_score ?? 0
  );

  const formattedRiskScore =
    Number.isFinite(riskScore)
      ? riskScore.toFixed(2)
      : "N/A";

  // -----------------------------------------
  // Render Component
  // -----------------------------------------

  return (
    <section className="ai-explanation">
      <h3>AI Security Explanation</h3>

      {guestMode && (
        <p
          style={{
            fontSize: 13,
            opacity: 0.8,
            marginBottom: 12,
          }}
        >
          Guest explanation uses your current scan
          result. Your scan is not saved to Supabase.
        </p>
      )}

      <button
        type="button"
        onClick={handleGenerate}
        disabled={loading || !canGenerate}
        className="ai-generate-btn"
      >
        {loading
          ? "Generating explanation..."
          : result
            ? "Explanation Generated"
            : "Generate AI Explanation"}
      </button>

      {loading && (
        <p
          className="ai-loading"
          role="status"
        >
          {guestMode
            ? "Analyzing your temporary scan findings..."
            : "Analyzing the stored security findings..."}
        </p>
      )}

      {error && (
        <p
          className="ai-error"
          role="alert"
        >
          {error}
        </p>
      )}

      {result && (
        <div className="ai-result">
          <div className="ai-result-header">
            <span>
              {guestMode
                ? "Guest scan · Not saved"
                : `Scan ID: ${
                    result.scan_id ?? scanId
                  }`}
            </span>

            <span>
              Risk:{" "}
              {result.risk_level || "UNKNOWN"}{" "}
              ({formattedRiskScore}%)
            </span>
          </div>

          <p className="ai-model">
            Explanation source:{" "}
            <strong>{modelLabel}</strong>
          </p>

          {Array.isArray(result.indicators) &&
            result.indicators.length > 0 && (
              <div className="ai-section">
                <h4>Detected Indicators</h4>

                <ul>
                  {result.indicators.map(
                    (indicator, index) => (
                      <li key={index}>
                        {indicator}
                      </li>
                    )
                  )}
                </ul>
              </div>
            )}

          {hasStructuredSections ? (
            <>
              {assessment && (
                <div className="ai-section">
                  <h4>Assessment</h4>
                  <p>{assessment}</p>
                </div>
              )}

              {reason && (
                <div className="ai-section">
                  <h4>Reason</h4>
                  <p>{reason}</p>
                </div>
              )}

              {recommendation && (
                <div className="ai-section">
                  <h4>Recommendation</h4>
                  <p>{recommendation}</p>
                </div>
              )}
            </>
          ) : (
            <div className="ai-section">
              <h4>AI Explanation</h4>

              <p
                style={{
                  whiteSpace: "pre-wrap",
                }}
              >
                {result.explanation}
              </p>
            </div>
          )}

          {result.disclaimer && (
            <p className="ai-disclaimer">
              {result.disclaimer}
            </p>
          )}
        </div>
      )}
    </section>
  );
}
