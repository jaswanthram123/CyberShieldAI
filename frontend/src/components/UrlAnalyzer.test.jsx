
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

import UrlAnalyzer from "./UrlAnalyzer";

vi.mock("../services/api", () => ({
  analyzeUrl: vi.fn(),
}));

vi.mock("./AiExplanation", () => ({
  default: () => null,
}));

import { analyzeUrl } from "../services/api";

describe("CyberShield AI URL Analyzer", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders the URL analyzer", () => {
    render(<UrlAnalyzer />);

    expect(
      screen.getByRole("heading", {
        name: "AI URL Analyzer",
      })
    ).toBeTruthy();

    expect(
      screen.getByPlaceholderText("https://example.com")
    ).toBeTruthy();
  });

  it("rejects an empty URL", async () => {
    render(<UrlAnalyzer />);

    fireEvent.click(
      screen.getByRole("button", { name: "Analyze URL" })
    );

    expect(
      await screen.findByText("Please enter a URL.")
    ).toBeTruthy();

    expect(analyzeUrl).not.toHaveBeenCalled();
  });

  it("rejects URLs without http or https", async () => {
    render(<UrlAnalyzer />);

    fireEvent.change(
      screen.getByPlaceholderText("https://example.com"),
      { target: { value: "example.com" } }
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Analyze URL" })
    );

    expect(
      await screen.findByText(
        "Enter a URL starting with http:// or https://"
      )
    ).toBeTruthy();

    expect(analyzeUrl).not.toHaveBeenCalled();
  });

  it("rejects multiple URLs", async () => {
    render(<UrlAnalyzer />);

    fireEvent.change(
      screen.getByPlaceholderText("https://example.com"),
      {
        target: {
          value: "https://example.com https://test.com",
        },
      }
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Analyze URL" })
    );

    expect(analyzeUrl).not.toHaveBeenCalled();

    expect(
      await screen.findByRole("alert")
    ).toBeTruthy();
  });

  it("analyzes a valid URL", async () => {
    const onScanComplete = vi.fn();

    analyzeUrl.mockResolvedValue({
      scan_id: 1,
      prediction: "LEGITIMATE",
      risk_level: "LOW",
      risk_score: 10,
      explanation: "No major suspicious indicators found.",
      indicators: [],
    });

    render(
      <UrlAnalyzer onScanComplete={onScanComplete} />
    );

    fireEvent.change(
      screen.getByPlaceholderText("https://example.com"),
      {
        target: { value: "https://example.com" },
      }
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Analyze URL" })
    );

    await waitFor(() => {
      expect(analyzeUrl).toHaveBeenCalledWith(
        "https://example.com"
      );
    });

    expect(
      await screen.findByText("URL Analysis Result")
    ).toBeTruthy();

    expect(
      screen.getByText(
        "No major suspicious indicators found."
      )
    ).toBeTruthy();

    await waitFor(() => {
      expect(onScanComplete).toHaveBeenCalledOnce();
    });
  });

  it("displays an API error", async () => {
    analyzeUrl.mockRejectedValue({
      response: {
        status: 400,
        data: {
          detail: "Invalid URL format",
        },
      },
    });

    render(<UrlAnalyzer />);

    fireEvent.change(
      screen.getByPlaceholderText("https://example.com"),
      {
        target: { value: "https://example.com" },
      }
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Analyze URL" })
    );

    expect(
      await screen.findByText("Invalid URL format")
    ).toBeTruthy();
  });
});
