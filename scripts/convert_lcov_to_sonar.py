#!/usr/bin/env python3
"""Convert cargo-llvm-cov LCOV output to SonarCloud generic coverage XML."""
import os
import sys
from xml.etree.ElementTree import Element, SubElement, tostring

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LCOV_PATH = os.path.join(REPO_ROOT, "dlp-agent-lcov.info")
OUTPUT_PATH = os.path.join(REPO_ROOT, "dlp-agent-generic-coverage.xml")


def parse_lcov(path: str) -> dict[str, dict[int, int]]:
    files: dict[str, dict[int, int]] = {}
    current_file: str | None = None
    current_hits: dict[int, int] = {}

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line.startswith("SF:"):
                current_file = line[3:]
                current_hits = {}
            elif line.startswith("DA:"):
                parts = line[3:].split(",")
                if len(parts) >= 2:
                    line_no = int(parts[0])
                    hits = int(parts[1])
                    current_hits[line_no] = current_hits.get(line_no, 0) + hits
            elif line == "end_of_record":
                if current_file is not None:
                    # Prefer the file with the most coverage data when LCOV repeats files.
                    if current_file not in files or len(current_hits) > len(
                        files[current_file]
                    ):
                        files[current_file] = current_hits
                current_file = None
                current_hits = {}
    return files


def make_relative(path: str, root: str) -> str | None:
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return None
    if rel.startswith(".."):
        return None
    return rel.replace(os.sep, "/")


def main() -> int:
    if not os.path.exists(LCOV_PATH):
        print(f"LCOV file not found: {LCOV_PATH}", file=sys.stderr)
        return 1

    coverage = Element("coverage", {"version": "1"})
    files = parse_lcov(LCOV_PATH)

    for abs_path, hits in sorted(files.items()):
        rel = make_relative(abs_path, REPO_ROOT)
        if rel is None:
            continue
        if not rel.endswith(".rs"):
            continue
        file_elem = SubElement(coverage, "file", {"path": rel})
        for line_no in sorted(hits):
            SubElement(
                file_elem,
                "lineToCover",
                {
                    "lineNumber": str(line_no),
                    "covered": "true" if hits[line_no] > 0 else "false",
                },
            )

    xml_bytes = tostring(coverage, encoding="unicode")
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(xml_bytes)
        f.write("\n")

    print(f"Wrote Sonar generic coverage to {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
