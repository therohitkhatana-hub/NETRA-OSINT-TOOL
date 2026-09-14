"""
CLI entrypoint for NETRA.
Runs the full pipeline and produces an investigator-ready PDF report.

Usage:
    python main.py --phone "+919876543210"
    python main.py --email "suspect@example.com"
    python main.py --phone "+919876543210" --email "suspect@example.com"
    python main.py --phone "+919876543210" --email "suspect@example.com" --out netra_report.pdf
"""
import argparse
import warnings
from dotenv import load_dotenv
from orchestrator import investigate
from report import generate_pdf

warnings.filterwarnings("ignore")
load_dotenv()


def print_findings(label: str, findings: list):
    if not findings:
        return
    print(f"\n--- {label} ---")
    for f in sorted(findings, key=lambda x: -x.confidence):
        tier = "HIGH" if f.confidence >= 0.75 else "MED" if f.confidence >= 0.5 else "LOW"
        print(f"  [{tier} conf={f.confidence:.2f}] ({f.source}) {f.fact}")


def main():
    print("=" * 60)
    print("  NETRA - Cyber Crime OSINT Tool")
    print("  Jaipur Police Cyber Crime Dept | Rohit Khatana")
    print("=" * 60)

    parser = argparse.ArgumentParser(description="NETRA - phone & email investigator tool")
    parser.add_argument("--phone", help="Phone number, e.g. +919876543210")
    parser.add_argument("--email", help="Email address to investigate")
    parser.add_argument("--out", default="netra_report.pdf", help="Output PDF path (default: netra_report.pdf)")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF generation, console output only")
    args = parser.parse_args()

    if not args.phone and not args.email:
        parser.error("Provide at least --phone or --email")

    print(f"Investigating: phone={args.phone or '-'} email={args.email or '-'}")
    result = investigate(phone=args.phone, email=args.email)

    print_findings("PHONE FINDINGS", result["phone_findings"])
    print_findings("EMAIL FINDINGS", result["email_findings"])
    print_findings("CROSS-LINKAGE FINDINGS", result["linkage_findings"])
    print("\nAll findings saved to database.")

    if not args.no_pdf:
        path = generate_pdf(result, args.phone, args.email, output_path=args.out)
        print(f"Dossier PDF written to: {path}")


if __name__ == "__main__":
    main()
