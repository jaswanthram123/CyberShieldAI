
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";

import App from "./App";

vi.mock("./services/api", () => ({
  login: vi.fn(),
  checkBackendHealth: vi.fn(),
  getTotalScans: vi.fn(),
  getAllScans: vi.fn(),
  analyzeMessage: vi.fn(),
  clearCredentials: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
}));

vi.mock("./components/UrlAnalyzer", () => ({
  default: () => <div>URL Analyzer Test Page</div>,
}));

vi.mock("./components/FileAnalyzer", () => ({
  default: () => <div>File Analyzer Test Page</div>,
}));

vi.mock("./components/ThreatIntelligence", () => ({
  default: () => <div>Threat Intelligence Test Page</div>,
}));

vi.mock("./components/AiExplanation", () => ({
  default: () => null,
}));

import {
  login,
  checkBackendHealth,
  getTotalScans,
  getAllScans,
  clearCredentials,
} from "./services/api";

describe("CyberShield AI Dashboard", () => {
  beforeEach(() => {
    vi.resetAllMocks();

    login.mockResolvedValue(true);

    checkBackendHealth.mockResolvedValue({
      status: "UP",
    });

    getTotalScans.mockResolvedValue({
      totalScans: 0,
    });

    getAllScans.mockResolvedValue([]);
  });

  afterEach(() => {
    cleanup();
  });

  async function signIn() {
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "test-password" },
    });

    fireEvent.click(
      screen.getByRole("button", {
        name: "Sign In",
      })
    );

    await screen.findByRole("heading", {
      name: "Security Overview",
    });
  }

  it("shows the login page initially", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", {
        name: "CyberShield AI",
      })
    ).toBeTruthy();
  });

  it("displays the dashboard after login", async () => {
    render(<App />);

    await signIn();

    expect(
      screen.getByText("Total Scans")
    ).toBeTruthy();

    await waitFor(() => {
      expect(checkBackendHealth).toHaveBeenCalled();
      expect(getTotalScans).toHaveBeenCalled();
    });
  });

  it("navigates to the URL Analyzer", async () => {
    render(<App />);

    await signIn();

    fireEvent.click(
      screen.getByRole("button", {
        name: "URL Analyzer",
      })
    );

    expect(
      screen.getByText("URL Analyzer Test Page")
    ).toBeTruthy();
  });

  it("navigates to the File Analyzer", async () => {
    render(<App />);

    await signIn();

    fireEvent.click(
      screen.getByRole("button", {
        name: "File Analyzer",
      })
    );

    expect(
      screen.getByText("File Analyzer Test Page")
    ).toBeTruthy();
  });

  it("logs out successfully", async () => {
    render(<App />);

    await signIn();

    const logoutButtons = screen.getAllByRole("button", {
      name: "Logout",
    });

    expect(logoutButtons).toHaveLength(2);

    fireEvent.click(logoutButtons[0]);

    expect(
      await screen.findByRole("button", {
        name: "Sign In",
      })
    ).toBeTruthy();

    expect(clearCredentials).toHaveBeenCalled();
  });
});
