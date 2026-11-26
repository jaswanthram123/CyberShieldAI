
import { useState } from "react";
import { generateAiExplanation } from "../services/api";

export default function AiExplanation({ scanId }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleGenerate() {
    if (!Number.isInteger(Number(scanId)) || Number(scanId) <= 0) {
      setError("Invalid scan ID.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await generateAiExplanation(scanId);

      if (response.data?.status !== "COMPLETED") {
        throw new Error("Explanation was not completed.");
      }

      setResult(response.data);
    } catch (err) {
      setError(
        err.response?.data?.message ||
        err.message ||
        "Unable to generate AI explanation."
      );
    } finally {
      setLoading(false);
    }
  }

  function getSection(name) {
    if (!result?.explanation) return "";

    const headings = [
      "Assessment:",
      "Reason:",
      "Recommendation:",
    ];

    const start = result.explanation.indexOf(name);

    if (start === -1) return "";

    const contentStart = start + name.length;

    const nextPositions = headings
      .filter((heading) => heading !== name)
      .map((heading) =>
        result.explanation.indexOf(heading, contentStart)
      )
      .filter((position) => position !== -1);

    const end = nextPositions.length
      ? Math.min(...nextPositions)
      : result.explanation.length;

    return result.explanation
      .slice(contentStart, end)
      .trim();
  }

  return (
    <section className="ai-explanation">
      <h3>AI Security Explanation</h3>

      <button
        type="button"
        onClick={handleGenerate}
        disabled={loading}
        className="ai-generate-btn"
      >
        {loading
          ? "Generating explanation..."
          : "Generate AI Explanation"}
      </button>

      {loading && (
        <p className="ai-loading">
          Analyzing the stored security findings...
        </p>
      )}

      {error && (
        <p className="ai-error" role="alert">
          {error}
        </p>
      )}

      {result && (
        <div className="ai-result">
          <div className="ai-result-header">
            <span>
              Scan ID: {result.scan_id}
            </span>

            <span>
              Risk: {result.risk_level} (
              {Number(result.risk_score).toFixed(2)}%)
            </span>
          </div>

          <p className="ai-model">
            Explanation source:{" "}
            {result.model?.startsWith("deterministic")
              ? "Predefined explanation"
              : `Gemini AI (${result.model})`}
          </p>

          {Array.isArray(result.indicators) &&
            result.indicators.length > 0 && (
              <div className="ai-section">
                <h4>Detected Indicators</h4>

                <ul>
                  {result.indicators.map((indicator, index) => (
                    <li key={index}>
                      {indicator}
                    </li>
                  ))}
                </ul>
              </div>
            )}

          <div className="ai-section">
            <h4>Assessment</h4>
            <p>{getSection("Assessment:")}</p>
          </div>

          <div className="ai-section">
            <h4>Reason</h4>
            <p>{getSection("Reason:")}</p>
          </div>

          <div className="ai-section">
            <h4>Recommendation</h4>
            <p>{getSection("Recommendation:")}</p>
          </div>

          <p className="ai-disclaimer">
            {result.disclaimer}
          </p>
        </div>
      )}
    </section>
  );
}

