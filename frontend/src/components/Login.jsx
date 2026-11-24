
import { useState } from "react";
import { login } from "../services/api";

export default function Login({ onLogin }) {
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

        {error && <p className="login-error">{error}</p>}

        <button type="submit" disabled={loading}>
          {loading ? "Signing in..." : "Sign In"}
        </button>
      </form>
    </div>
  );
}
