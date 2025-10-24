🧩 Nessus CSV Summarizer (No External Libraries)

This Python script processes a Nessus CSV export and generates a clean, summarized CSV report with hosts, open ports, and vulnerability notes — without requiring any external dependencies like pandas.

⸻

🚀 Features
	•	Pure Python (no external libraries) — works out-of-the-box on any system with Python 3.
	•	Aggregates data by host
	•	Collects unique ports (e.g., tcp 22, udp 53) for each host.
	•	Ignores ports with value 0.
	•	CVE and Risk extraction
	•	Extracts CVE identifiers automatically from the Nessus report.
	•	Includes risk levels if available.
	•	Cleans output
	•	Deduplicates and merges CVEs and Risks for each host.
	•	Leaves Main service column blank (for manual use later).

⸻
🧾 Input Requirements

You must export your Nessus scan as a CSV using “All available columns” (i.e., all components selected).
The script expects at least the following columns to exist (case-insensitive):
Required
- Host
- Port
- Protocol

Optional
- CVE
- Risk

If you include all components during export, Nessus will automatically include these.

📦 Usage

1️⃣ Save the script

Save the Python file as summarize_nessus.py in your working directory.

2️⃣ Run it

From your terminal:
python3 summarize_nessus.py input_report.csv summary_output.csv


⚙️ Notes
	•	Ports with value 0 are ignored.
	•	CVEs are detected in any format like CVE-2023-XXXX.
	•	Risk values such as Low, Medium, High, or Critical are included only if not empty or None.
	•	Works fully offline — no third-party dependencies required.


📁 Recommended Nessus Export Settings

When exporting from Tenable Nessus:
	1.	Go to your completed scan.
	2.	Click Export → CSV.
	3.	Select All components (every column).
	4.	Save the file (e.g., my_scan_report.csv).
	5.	Use that as your input to this script.
