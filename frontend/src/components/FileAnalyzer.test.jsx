
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

import FileAnalyzer from "./FileAnalyzer";

vi.mock("../services/api", () => ({
  analyzeFile: vi.fn(),
}));

vi.mock("./AiExplanation", () => ({
  default: () => null,
}));

import { analyzeFile } from "../services/api";

describe("CyberShield AI File Analyzer", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  function uploadFile(file) {
    const input = document.querySelector('input[type="file"]');

    fireEvent.change(input, {
      target: { files: [file] },
    });
  }

  it("renders the file analyzer", () => {
    render(<FileAnalyzer />);

    expect(
      screen.getByRole("heading", {
        name: "AI File Analyzer",
      })
    ).toBeTruthy();

    expect(
      screen.getByRole("button", {
        name: "Choose File",
      })
    ).toBeTruthy();
  });

  it("disables analysis when no file is selected", () => {
    render(<FileAnalyzer />);

    expect(
      screen.getByRole("button", {
        name: "Analyze File",
      }).disabled
    ).toBe(true);
  });

  it("rejects empty files", async () => {
    render(<FileAnalyzer />);

    const file = new File([], "empty.txt", {
      type: "text/plain",
    });

    uploadFile(file);

    expect(
      await screen.findByText(
        "Empty files are not supported."
      )
    ).toBeTruthy();

    expect(analyzeFile).not.toHaveBeenCalled();
  });

  it("rejects files larger than 10 MB", async () => {
    render(<FileAnalyzer />);

    const file = new File(
      [new Uint8Array(10 * 1024 * 1024 + 1)],
      "large.txt",
      { type: "text/plain" }
    );

    uploadFile(file);

    expect(
      await screen.findByText(
        "Maximum file size is 10 MB."
      )
    ).toBeTruthy();

    expect(analyzeFile).not.toHaveBeenCalled();
  });

  it("accepts a valid file", () => {
    render(<FileAnalyzer />);

    const file = new File(
      ["CyberShield AI test"],
      "sample.txt",
      { type: "text/plain" }
    );

    uploadFile(file);

    expect(
      screen.getByText("sample.txt")
    ).toBeTruthy();

    expect(
      screen.getByRole("button", {
        name: "Analyze File",
      }).disabled
    ).toBe(false);
  });

  it("removes a selected file", () => {
    render(<FileAnalyzer />);

    uploadFile(
      new File(["test"], "sample.txt", {
        type: "text/plain",
      })
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: "Remove selected file",
      })
    );

    expect(
      screen.queryByText("sample.txt")
    ).toBeNull();
  });

  it("analyzes a valid file successfully", async () => {
    const onScanComplete = vi.fn();

    analyzeFile.mockResolvedValue({
      status: "COMPLETED",
      scan_id: 0,
      filename: "sample.txt",
      file_extension: ".txt",
      file_size: 4,
      sha256: "abc123",
      prediction: "LEGITIMATE",
      risk_level: "LOW",
      risk_score: 5,
      indicators: [],
      explanation: "No suspicious patterns found.",
    });

    render(
      <FileAnalyzer onScanComplete={onScanComplete} />
    );

    uploadFile(
      new File(["test"], "sample.txt", {
        type: "text/plain",
      })
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: "Analyze File",
      })
    );

    await waitFor(() => {
      expect(analyzeFile).toHaveBeenCalledOnce();
    });

    expect(
      await screen.findByText("File Analysis Result")
    ).toBeTruthy();

    expect(
      screen.getByText("No suspicious patterns found.")
    ).toBeTruthy();

    await waitFor(() => {
      expect(onScanComplete).toHaveBeenCalledOnce();
    });
  });

  it("displays an API error", async () => {
    analyzeFile.mockRejectedValue({
      response: {
        status: 400,
        data: {
          detail: "Unsupported file format",
        },
      },
    });

    render(<FileAnalyzer />);

    uploadFile(
      new File(["test"], "sample.txt", {
        type: "text/plain",
      })
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: "Analyze File",
      })
    );

    expect(
      await screen.findByText("Unsupported file format")
    ).toBeTruthy();
  });
});
