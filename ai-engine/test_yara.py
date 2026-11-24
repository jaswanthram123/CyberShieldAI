
from yara_scanner import scan_with_yara

tests = {
    "normal_text": b"Hello, this is a normal file.",

    "test_marker": (
        b"CYBERSHIELD_YARA_TEST_2026"
    ),

    "pdf_javascript": (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /OpenAction 2 0 R /JavaScript "
        b"(test) >>\n"
        b"endobj\n"
        b"%%EOF"
    ),

    "pdf_launch": (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Launch >>\n"
        b"endobj\n"
        b"%%EOF"
    ),
}

for name, content in tests.items():
    result = scan_with_yara(content)

    print("\n------------------------")
    print("Test:", name)
    print("Status:", result["status"])
    print("YARA score:", result["score"])

    for match in result["matches"]:
        print("Matched:", match["rule"])
        print("Severity:", match["severity"])

