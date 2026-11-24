
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Login from "./Login";

vi.mock("../services/api", () => ({
  login: vi.fn(),
}));

import { login } from "../services/api";

describe("CyberShield AI Login", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders the login form", () => {
    render(<Login onLogin={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "CyberShield AI" })).toBeTruthy();
    expect(screen.getByLabelText("Username").value).toBe("developer");
    expect(screen.getByLabelText("Password")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sign In" })).toBeTruthy();
  });

  it("logs in successfully with valid credentials", async () => {
    const onLogin = vi.fn();
    login.mockResolvedValue({});

    render(<Login onLogin={onLogin} />);

    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "test-password" },
    });

    fireEvent.click(screen.getByRole("button", { name: "Sign In" }));

    await waitFor(() => {
      expect(login).toHaveBeenCalledWith("developer", "test-password");
      expect(onLogin).toHaveBeenCalledOnce();
    });
  });

  it("shows an error for invalid credentials", async () => {
    const onLogin = vi.fn();
    login.mockRejectedValue({ response: { status: 401 } });

    render(<Login onLogin={onLogin} />);

    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "wrong-password" },
    });

    fireEvent.click(screen.getByRole("button", { name: "Sign In" }));

    expect(await screen.findByText("Invalid username or password.")).toBeTruthy();
    expect(onLogin).not.toHaveBeenCalled();
  });

  it("does not submit without a password", () => {
    render(<Login onLogin={vi.fn()} />);

    const password = screen.getByLabelText("Password");

    expect(password.required).toBe(true);
    expect(password.value).toBe("");
  });
});
