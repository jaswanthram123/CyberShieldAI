
import { useCallback, useEffect, useState } from "react";

import {
  Activity,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  ScanLine,
  RefreshCw,
  FileText,
  Link2,
  FileSearch,
} from "lucide-react";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

import {
  getThreatIntelligenceSummary,
} from "../services/api";

const COLORS = {
  HIGH: "#ef4444",
  MEDIUM: "#f59e0b",
  LOW: "#22c55e",
  MESSAGE: "#6366f1",
  URL: "#06b6d4",
  FILE: "#a855f7",
};

function StatCard({ title, value, icon: Icon, color }) {
  return (
    <div
      className="panel"
      style={{
        padding: 20,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 12,
      }}
    >
      <div>
        <p style={{ marginBottom: 8, opacity: 0.75 }}>
          {title}
        </p>

        <h2 style={{ fontSize: 30, margin: 0 }}>
          {value}
        </h2>
      </div>

      <Icon size={30} color={color} />
    </div>
  );
}

function formatDate(value) {
  if (!value) return "N/A";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "N/A";
  }

  return date.toLocaleString();
}

export default function ThreatIntelligence() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const loadSummary = useCallback(async (refresh = false) => {
    if (refresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    setError("");

    try {
      const data = await getThreatIntelligenceSummary();
      setSummary(data);
    } catch (err) {
      if (err.response?.status === 401) {
        return;
      }

      setError(
        err.response?.data?.message ||
          "Unable to load threat intelligence data."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function fetchInitialSummary() {
      try {
        const data = await getThreatIntelligenceSummary();
        if (!cancelled) {
          setSummary(data);
          setError("");
        }
      } catch (err) {
        if (!cancelled && err.response?.status !== 401) {
          setError(
            err.response?.data?.message ||
              "Unable to load threat intelligence data."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    fetchInitialSummary();

    return () => {
      cancelled = true;
    };
  }, []);

  const total = summary?.totalScans ?? 0;
  const high = summary?.highRisk ?? 0;
  const medium = summary?.mediumRisk ?? 0;
  const low = summary?.lowRisk ?? 0;

  const riskData = [
    { name: "High", value: high, color: COLORS.HIGH },
    { name: "Medium", value: medium, color: COLORS.MEDIUM },
    { name: "Low", value: low, color: COLORS.LOW },
  ];

  const typeData = [
    {
      name: "Messages",
      count: summary?.messageScans ?? 0,
      fill: COLORS.MESSAGE,
    },
    {
      name: "URLs",
      count: summary?.urlScans ?? 0,
      fill: COLORS.URL,
    },
    {
      name: "Files",
      count: summary?.fileScans ?? 0,
      fill: COLORS.FILE,
    },
  ];

  const highRiskScans = summary?.recentHighRisk ?? [];

  if (loading) {
    return (
      <div className="panel" style={{ padding: 30 }}>
        <p>Loading threat intelligence...</p>
      </div>
    );
  }

  return (
    <div>
      <div
        className="page-heading"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 15,
          flexWrap: "wrap",
        }}
      >
        <div>
          <h1>Threat Intelligence</h1>
          <p>
            Unified security insights from message, URL,
            and file scans.
          </p>
        </div>

        <button
          type="button"
          className="primary-button"
          onClick={() => loadSummary(true)}
          disabled={refreshing}
        >
          <RefreshCw size={17} />
          {refreshing ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="alert-message" role="alert">
          <AlertTriangle size={18} />
          {" "}{error}
        </div>
      )}

      {!summary ? (
        <div className="panel" style={{ padding: 25 }}>
          <p>No threat intelligence data available.</p>
        </div>
      ) : (
        <>
          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "repeat(auto-fit, minmax(190px, 1fr))",
              gap: 18,
              marginBottom: 24,
            }}
          >
            <StatCard
              title="Total Scans"
              value={total}
              icon={ScanLine}
              color="#6366f1"
            />

            <StatCard
              title="High Risk"
              value={high}
              icon={ShieldAlert}
              color={COLORS.HIGH}
            />

            <StatCard
              title="Medium Risk"
              value={medium}
              icon={AlertTriangle}
              color={COLORS.MEDIUM}
            />

            <StatCard
              title="Low Risk"
              value={low}
              icon={ShieldCheck}
              color={COLORS.LOW}
            />
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "repeat(auto-fit, minmax(280px, 1fr))",
              gap: 20,
              marginBottom: 24,
            }}
          >
            <div className="panel" style={{ padding: 22 }}>
              <h2 style={{ marginBottom: 20 }}>
                Risk Distribution
              </h2>

              {high + medium + low === 0 ? (
                <p>No classified scans available.</p>
              ) : (
                <div style={{ height: 300 }}>
                  <ResponsiveContainer
                    width="100%"
                    height="100%"
                  >
                    <PieChart>
                      <Pie
                        data={riskData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="45%"
                        innerRadius={55}
                        outerRadius={90}
                        label
                      >
                        {riskData.map((item) => (
                          <Cell
                            key={item.name}
                            fill={item.color}
                          />
                        ))}
                      </Pie>

                      <Tooltip />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>

            <div className="panel" style={{ padding: 22 }}>
              <h2 style={{ marginBottom: 20 }}>
                Scan Type Breakdown
              </h2>

              {total === 0 ? (
                <p>No scans available.</p>
              ) : (
                <div style={{ height: 300 }}>
                  <ResponsiveContainer
                    width="100%"
                    height="100%"
                  >
                    <BarChart data={typeData}>
                      <CartesianGrid
                        strokeDasharray="3 3"
                        opacity={0.2}
                      />

                      <XAxis
                        dataKey="name"
                        tick={{ fill: "#94a3b8" }}
                      />

                      <YAxis
                        allowDecimals={false}
                        tick={{ fill: "#94a3b8" }}
                      />

                      <Tooltip />

                      <Bar
                        dataKey="count"
                        name="Scans"
                        radius={[6, 6, 0, 0]}
                      >
                        {typeData.map((item) => (
                          <Cell
                            key={item.name}
                            fill={item.fill}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </div>

          <div className="panel" style={{ padding: 22 }}>
            <h2 style={{ marginBottom: 20 }}>
              <Activity
                size={20}
                style={{
                  display: "inline",
                  marginRight: 8,
                }}
              />
              Recent High-Risk Scans
            </h2>

            {highRiskScans.length === 0 ? (
              <p>No high-risk scans found.</p>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table
                  style={{
                    width: "100%",
                    borderCollapse: "collapse",
                    textAlign: "left",
                  }}
                >
                  <thead>
                    <tr>
                      {[
                        "Scan ID",
                        "Type",
                        "Risk",
                        "Score",
                        "Date",
                      ].map((heading) => (
                        <th
                          key={heading}
                          style={{
                            padding: 12,
                            borderBottom:
                              "1px solid #475569",
                          }}
                        >
                          {heading}
                        </th>
                      ))}
                    </tr>
                  </thead>

                  <tbody>
                    {highRiskScans.map((scan) => (
                      <tr key={scan.id}>
                        <td style={{ padding: 12 }}>
                          #{scan.id}
                        </td>

                        <td style={{ padding: 12 }}>
                          {scan.scanType === "MESSAGE" && (
                            <FileText
                              size={15}
                              style={{
                                display: "inline",
                                marginRight: 6,
                              }}
                            />
                          )}

                          {scan.scanType === "URL" && (
                            <Link2
                              size={15}
                              style={{
                                display: "inline",
                                marginRight: 6,
                              }}
                            />
                          )}

                          {scan.scanType === "FILE" && (
                            <FileSearch
                              size={15}
                              style={{
                                display: "inline",
                                marginRight: 6,
                              }}
                            />
                          )}

                          {scan.scanType}
                        </td>

                        <td style={{ padding: 12 }}>
                          <span className="risk-badge risk-high">
                            HIGH
                          </span>
                        </td>

                        <td style={{ padding: 12 }}>
                          {Number(
                            scan.riskScore ?? 0
                          ).toFixed(2)}%
                        </td>

                        <td style={{ padding: 12 }}>
                          {formatDate(scan.createdAt)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div
            className="panel"
            style={{ padding: 18, marginTop: 20 }}
          >
            <p style={{ opacity: 0.8 }}>
              This dashboard summarizes stored heuristic
              and demonstration-model results. Risk
              scores are not verified malware or threat
              intelligence verdicts.
            </p>
          </div>
        </>
      )}
    </div>
  );
}
