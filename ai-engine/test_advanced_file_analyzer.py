
from io import BytesIO
import zipfile

from advanced_file_analyzer import analyze_file_advanced


def show_result(filename, content):
    result = analyze_file_advanced(filename, content)

    print("\n-----------------------------")
    print("File:", filename)
    print("Risk score:", result["risk_score"])
    print("Risk level:", result["risk_level"])
    print("Prediction:", result["prediction"])
    print("Indicators:")

    for indicator in result["indicators"]:
        print("-", indicator)


# Test 1: Normal text file
show_result(
    "notes.txt",
    b"Hello, this is a normal text file."
)


# Test 2: PDF with an illustrative action marker
pdf_content = (
    b"%PDF-1.4\n"
    b"1 0 obj\n"
    b"<< /Type /Catalog /OpenAction 2 0 R >>\n"
    b"endobj\n"
    b"%%EOF\n"
)

show_result("sample.pdf", pdf_content)


# Test 3: ZIP containing a harmless script-named entry
buffer = BytesIO()

with zipfile.ZipFile(buffer, "w") as archive:
    archive.writestr(
        "readme.txt",
        "This is a test archive."
    )

    archive.writestr(
        "example.js",
        "// harmless test content"
    )

show_result("sample.zip", buffer.getvalue())


# Test 4: Harmless ZIP archive
normal_zip = BytesIO()

with zipfile.ZipFile(normal_zip, "w") as archive:
    archive.writestr(
        "document.txt",
        "Normal document."
    )

show_result("normal.zip", normal_zip.getvalue())
