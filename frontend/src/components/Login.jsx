import { useState } from "react";
import { login } from "../services/api";

export default function Login({ onLogin, onGuest }) {
  const [username, setUsername] = useState("developer");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      await login(username, password);
      onLogin();
    } catch (err) {
      setError(
        err.response?.status === 401
          ? "Invalid username or password."
          : "Unable to log in. Check your backend connection."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-logo">🛡️</div>

        <h1>CyberShield AI</h1>
        <p>Sign in to your security dashboard</p>

        <label htmlFor="username">Username</label>
        <input
          id="username"
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
          autoComplete="username"
        />

        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoComplete="current-password"
        />

        {error && <p className="login-error" role="alert">{error}</p>}

        <button type="submit" disabled={loading}>
          {loading ? "Signing in..." : "Sign In"}
        </button>

        <p style={{ textAlign: "center", margin: "16px 0 10px" }}>
          OR
        </p>

        <button
          type="button"
          onClick={onGuest}
          disabled={loading}
          style={{
            width: "100%",
            padding: "12px",
            background: "transparent",
            border: "1px solid #64748b",
            borderRadius: "8px",
            color: "inherit",
            cursor: "pointer",
          }}
        >
          Continue as Guest
        </button>

        <p style={{ fontSize: "12px", textAlign: "center", marginTop: "12px" }}>
          No account required. Guest scans are not saved to your dashboard.
        </p>
      </form>
    </div>
  );
}
