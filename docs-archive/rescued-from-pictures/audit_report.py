import os
from datetime import datetime

# --- Configuration ---
LOG_FILES = {
    "Defensive": "sentinel_actions.txt",
    "Offensive": "exfiltration_manifest.txt",
    "Intelligence": "intel_report.txt"
}
REPORT_NAME = f"Security_Audit_Report_{datetime.now().strftime('%Y%m%d')}.txt"

def generate_report():
    print(f"[*] Generating Master Audit Report: {REPORT_NAME}")
    
    with open(REPORT_NAME, "w") as report:
        report.write("==================================================\n")
        report.write("          1000% SECURITY ARCHITECT REPORT         \n")
        report.write(f"          Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write("==================================================\n\n")

        # 1. Summary Section
        report.write("## EXECUTIVE SUMMARY\n")
        report.write("The system was monitored under the Fortress Command protocol.\n")
        report.write("Both Defensive Traps and Offensive Audits were executed.\n\n")

        # 2. Extract Data from Log Files
        for category, filename in LOG_FILES.items():
            report.write(f"### {category} Activity Log\n")
            if os.path.exists(filename):
                with open(filename, "r") as log:
                    data = log.readlines()
                    if data:
                        # Write the last 10 events for brevity
                        for line in data[-10:]:
                            report.write(f"- {line}")
                    else:
                        report.write("No events recorded.\n")
            else:
                report.write(f"Log file {filename} not found. Module may not have been triggered.\n")
            report.write("\n")

        # 3. Final Risk Assessment Logic
        report.write("### FINAL SECURITY SCORE\n")
        # Example logic: if exfiltration log exists, risk is HIGH
        if os.path.exists("exfiltration_manifest.txt"):
            report.write("STATUS: CRITICAL VULNERABILITY DETECTED\n")
            report.write("Action Required: Patch immediate data leaks and reset credentials.\n")
        else:
            report.write("STATUS: SECURE\n")
            report.write("No unauthorized data movement detected.\n")

    print(f"[√] Report complete: {REPORT_NAME}")

if __name__ == "__main__":
    generate_report()