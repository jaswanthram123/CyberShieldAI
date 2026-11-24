
from io import BytesIO
from pathlib import PurePosixPath
import re
import zipfile

from file_analyzer import analyze_file as basic_analyze_file
from yara_scanner import scan_with_yara


# ---------------------------------------
# Configuration
# ---------------------------------------

MAX_ARCHIVE_ENTRIES = 1000
MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024
SUSPICIOUS_RATIO = 100


# ---------------------------------------
# PDF Static Analysis
# ---------------------------------------

def inspect_pdf(data):
    findings = []

    # Basic byte-pattern checks, not complete PDF parsing.

    if (
        b"/JavaScript" in data
        or re.search(rb"/JS\b", data)
    ):
        findings.append((
            35,
            "PDF contains a JavaScript action indicator"
        ))

    if b"/OpenAction" in data:
        findings.append((
            20,
            "PDF contains an automatic open-action indicator"
        ))

    if b"/Launch" in data:
        findings.append((
            35,
            "PDF contains an external launch-action indicator"
        ))

    if b"/EmbeddedFile" in data:
        findings.append((
            15,
            "PDF contains an embedded-file indicator"
        ))

    if re.search(rb"/AA\b", data):
        findings.append((
            15,
            "PDF contains an additional-action indicator"
        ))

    return findings


# ---------------------------------------
# ZIP and Office Archive Analysis
# ---------------------------------------

def inspect_zip(data):
    findings = []

    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:

            entries = archive.infolist()

            # Check number of entries.
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                findings.append((
                    25,
                    "Archive contains an unusually large "
                    "number of entries"
                ))

            # Check declared uncompressed size.
            total_uncompressed = sum(
                entry.file_size for entry in entries
            )

            total_compressed = sum(
                entry.compress_size for entry in entries
            )

            if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
                findings.append((
                    35,
                    "Archive declares more than 100 MB "
                    "of uncompressed content"
                ))

            # Check compression ratio.
            if total_uncompressed > 0:

                ratio = (
                    total_uncompressed
                    / max(total_compressed, 1)
                )

                if ratio >= SUSPICIOUS_RATIO:
                    findings.append((
                        35,
                        "Archive has a very high "
                        "compression ratio"
                    ))

            # Check encrypted entries.
            if any(
                entry.flag_bits & 0x1
                for entry in entries
            ):
                findings.append((
                    15,
                    "Archive contains encrypted entries "
                    "that cannot be fully inspected"
                ))

            # Read filenames only.
            # Never extract or execute archive contents.
            names = [
                entry.filename.replace("\\", "/").lower()
                for entry in entries
            ]

            # Check unsafe archive paths.
            for name in names:

                path = PurePosixPath(name)

                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or re.match(r"^[a-z]:/", name)
                ):
                    findings.append((
                        30,
                        "Archive contains a potentially "
                        "unsafe file path"
                    ))
                    break

            # Check executable and script filenames.
            suspicious_extensions = (
                ".exe",
                ".bat",
                ".cmd",
                ".ps1",
                ".vbs",
                ".js",
                ".scr",
                ".hta"
            )

            if any(
                name.endswith(suspicious_extensions)
                for name in names
            ):
                findings.append((
                    30,
                    "Archive contains a potentially "
                    "executable or script file"
                ))

            # Check VBA macro indicators.
            if any(
                name.endswith("vbaproject.bin")
                for name in names
            ):
                findings.append((
                    30,
                    "Archive contains an Office VBA "
                    "macro project indicator"
                ))

    except (
        zipfile.BadZipFile,
        ValueError,
        OSError,
        RuntimeError,
        NotImplementedError
    ):
        findings.append((
            20,
            "Archive structure could not "
            "be read reliably"
        ))

    return findings


# ---------------------------------------
# Risk Level Calculation
# ---------------------------------------

def calculate_risk_level(score):

    if score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


# ---------------------------------------
# Prediction Calculation
# ---------------------------------------

def calculate_prediction(score, indicators):

    if score >= 50:
        return "SUSPICIOUS"

    if indicators:
        return "INDICATORS_DETECTED"

    return "NO_INDICATORS_DETECTED"


# ---------------------------------------
# Advanced File Analyzer
# ---------------------------------------

def analyze_file_advanced(filename, data):

    # -----------------------------------
    # 1. Run existing basic analysis
    # -----------------------------------

    result = basic_analyze_file(filename, data)

    findings = []

    # -----------------------------------
    # 2. PDF Static Analysis
    # -----------------------------------

    if data[:1024].lstrip().startswith(b"%PDF-"):

        findings.extend(
            inspect_pdf(data)
        )

    # -----------------------------------
    # 3. ZIP / Office Archive Analysis
    # -----------------------------------

    if zipfile.is_zipfile(BytesIO(data)):

        findings.extend(
            inspect_zip(data)
        )

    # -----------------------------------
    # 4. Combine basic and advanced scores
    # -----------------------------------

    basic_score = float(
        result.get("risk_score", 0)
    )

    advanced_score = sum(
        points for points, _ in findings
    )

    static_score = round(
        min(
            100,
            max(0, basic_score + advanced_score)
        ),
        2
    )

    # -----------------------------------
    # 5. Combine detected indicators
    # -----------------------------------

    existing_indicators = list(
        result.get("indicators") or []
    )

    advanced_indicators = [
        description
        for _, description in findings
    ]

    all_indicators = list(
        dict.fromkeys(
            existing_indicators
            + advanced_indicators
        )
    )

    # -----------------------------------
    # 6. YARA Signature Detection
    # -----------------------------------

    yara_result = scan_with_yara(data)

    yara_matches = yara_result.get(
        "matches", []
    )

    yara_score = float(
        yara_result.get("score", 0)
    )

    yara_status = yara_result.get(
        "status", "ERROR"
    )

    yara_error = yara_result.get("error")

    # Add matched YARA rules as indicators.
    for match in yara_matches:

        indicator = (
            "YARA: "
            + match["rule"]
            + " - "
            + match["description"]
        )

        if indicator not in all_indicators:
            all_indicators.append(indicator)

    # -----------------------------------
    # 7. Calculate final combined score
    # -----------------------------------

    # Use maximum instead of adding YARA scores
    # to avoid double-counting overlapping checks.

    final_score = round(
        min(
            100,
            max(static_score, yara_score)
        ),
        2
    )

    risk_level = calculate_risk_level(
        final_score
    )

    prediction = calculate_prediction(
        final_score,
        all_indicators
    )

    # -----------------------------------
    # 8. Update original analysis result
    # -----------------------------------

    result["risk_score"] = final_score

    result["risk_level"] = risk_level

    result["prediction"] = prediction

    result["indicators"] = all_indicators

    result["advanced_indicators"] = (
        advanced_indicators
    )

    result["basic_risk_score"] = basic_score

    result["advanced_risk_score"] = (
        advanced_score
    )

    result["yara_risk_score"] = yara_score

    result["yara_matches"] = yara_matches

    result["yara_status"] = yara_status

    result["yara_error"] = yara_error

    result["model_version"] = (
        "file-static-yara-2.1"
    )

    # -----------------------------------
    # 9. Handle incomplete YARA scanning
    # -----------------------------------

    if yara_status != "COMPLETED":

        result["analysis_warning"] = (
            "YARA inspection did not complete. "
            "The file was only partially analyzed."
        )

    else:

        result["analysis_warning"] = None

    # -----------------------------------
    # 10. Explanation
    # -----------------------------------

    result["explanation"] = (
        "Static file analysis completed using "
        "filename, file signature, PDF byte-pattern, "
        "ZIP metadata, and YARA signature checks. "
        "Files were not executed or extracted. "
        "YARA inspection status: "
        + yara_status
        + ". These findings are heuristic indicators "
        "and do not confirm whether a file contains "
        "malware. Compressed, encrypted, or obfuscated "
        "content may evade detection."
    )

    return result
