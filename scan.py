"""
CLI Scanner for Vision-Language Model (VLM) Zero-Day Phishing Detection.
Usage:
    python scan.py <URL>
    python scan.py
"""
import sys
import json

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from backend.analyzer.pipeline import PhishingDetectionPipeline

def main():
    if len(sys.argv) > 1:
        target_url = sys.argv[1].strip()
    else:
        print("==================================================")
        print("   VLM ZERO-DAY PHISHING DETECTION SYSTEM (CLI)   ")
        print("==================================================")
        try:
            target_url = input("Enter Website URL to scan: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nScan cancelled.")
            sys.exit(0)

    if not target_url:
        print("[!] Error: No URL provided.")
        sys.exit(1)

    print(f"\n[*] Initiating multimodal inspection on: {target_url}")
    print("[*] Analyzing URL heuristics, DOM structures, text intent & visual features...")

    try:
        pipeline = PhishingDetectionPipeline()
        result = pipeline.analyze_url(target_url)
    except Exception as exc:
        print(f"\n[X] Scan failed: {exc}")
        sys.exit(1)

    classification = result.get("classification", "UNKNOWN")
    risk_score = result.get("risk_score", 0.0)
    confidence = result.get("confidence", 0.0)
    percentage = int(risk_score * 100)
    conf_percent = int(confidence * 100)

    # ANSI Formatting with ASCII indicators
    if classification == "PHISHING":
        badge = f"[!] PHISHING (CRITICAL THREAT)"
    elif classification == "SUSPICIOUS":
        badge = f"[?] SUSPICIOUS (ANOMALOUS ACTIVITY)"
    else:
        badge = f"[+] SAFE (LEGITIMATE / AUTHENTIC)"

    # Progress bar visualization (using ASCII safe characters)
    bar_len = 30
    filled = int(bar_len * risk_score)
    bar = "#" * filled + "-" * (bar_len - filled)

    print("\n" + "=" * 55)
    print("                 DETECTION RESULT                 ")
    print("=" * 55)
    print(f"Verdict:         {badge}")
    print(f"Risk Score:      [{bar}] {percentage}%")
    print(f"Confidence:      {conf_percent}%")
    if result.get("is_unreachable"):
        print(f"Host Status:     [!] OFFLINE / UNREACHABLE")
        if result.get("unreachable_reason"):
            print(f"Reason:          {result.get('unreachable_reason')[:70]}")

    sub = result.get("sub_scores", {})
    print("-" * 55)
    print("MODALITY RISK BREAKDOWN:")
    print(f"  - URL Risk:     {int(sub.get('url_score', 0) * 100)}%")
    print(f"  - Visual Risk:  {int(sub.get('visual_score', 0) * 100)}%")
    print(f"  - Text Risk:    {int(sub.get('text_score', 0) * 100)}%")
    print(f"  - HTML Risk:    {int(sub.get('html_score', 0) * 100)}%")

    indicators = result.get("categorized_indicators", {})
    has_indicators = any(len(lst) > 0 for lst in indicators.values())
    if has_indicators:
        print("-" * 55)
        print("KEY DETECTION INDICATORS:")
        for category, cat_list in indicators.items():
            for item in cat_list:
                print(f"  [{category.replace('_indicators', '').upper()}] {item}")

    explanations = result.get("explanation", [])
    if explanations:
        print("-" * 55)
        print("EXECUTIVE ASSESSMENT:")
        for exp in explanations:
            print(f"  * {exp}")

    print("=" * 55 + "\n")

if __name__ == "__main__":
    main()
