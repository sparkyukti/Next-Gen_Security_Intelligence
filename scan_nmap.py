import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime

DB_FILE = "cve_knowledge_graph.db"

# ==========================================
# 1. Advanced Translation & Fuzzy Matching Engine
# ==========================================
def normalize_and_find_match(cursor, service_info: str):
    """
    Normalizes the Nmap banner and searches for an onboarded Software entity.
    Uses an explicit translation map and keyword tokenization to prevent mismatches.
    """
    service_clean = service_info.lower().strip()
    
    # 🎯 Robust Local Translation Dictionary for known Nmap vs DB naming edge-cases
    NMAP_TO_DB_TRANSLATION = {
        "apache httpd": "apache http server",
        "httpd": "apache http server",
        "netkit-rsh": "netkit rshd",
        "rshd": "netkit rshd",
        "vnc": "realvnc"
    }
    
    # Check our translation map first
    for nmap_term, db_target in NMAP_TO_DB_TRANSLATION.items():
        if nmap_term in service_clean:
            service_clean = db_target
            break

    # Fetch all software currently registered in your Knowledge Graph
    cursor.execute("SELECT id, name, latest_version FROM software")
    all_software = cursor.fetchall()
    
    # Strategy A: Direct substring comparison on the translated/normalized name
    for sw_id, sw_name, latest_ver in all_software:
        name_clean = sw_name.lower()
        if name_clean in service_clean or service_clean in name_clean:
            return sw_id, sw_name, latest_ver

    # Strategy B: Tokenized Alphanumeric Overlap (Breaks "netkit-rsh" and "netkit rshd" down to common roots)
    def get_alphanumeric_tokens(text):
        return set(re.findall(r'[a-z0-9]+', text.lower()))

    service_tokens = get_alphanumeric_tokens(service_clean)
    # Filter out common meaningless generic network words
    service_tokens -= {"server", "http", "daemon", "service", "client"}

    for sw_id, sw_name, latest_ver in all_software:
        sw_tokens = get_alphanumeric_tokens(sw_name) - {"server", "http", "daemon", "service", "client"}
        
        # If they share significant alphanumeric root words, consider it a match
        if service_tokens and sw_tokens and (service_tokens.issubset(sw_tokens) or sw_tokens.issubset(service_tokens)):
            return sw_id, sw_name, latest_ver

    return None

# ==========================================
# 2. Knowledge Graph Query Engine
# ==========================================
def query_knowledge_graph(service_info: str):
    """
    Looks up a software product match inside the Knowledge Graph using advanced matching rules.
    """
    if not os.path.exists(DB_FILE):
        return {"status": "ERROR", "message": f"Database file '{DB_FILE}' not found."}

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Call the newly tuned matching logic
    matched_sw = normalize_and_find_match(cursor, service_info)
            
    if not matched_sw:
        conn.close()
        return {"status": "NOT_ONBOARDED"}
        
    sw_id, exact_name, latest_version = matched_sw
    
    # Extract potential version tags out of the Nmap info blob using clean boundary regex
    version_match = re.search(r'\b\d+(\.\d+)+[a-zA-Z0-9\-]*\b', service_info)
    if not version_match:
        conn.close()
        return {"status": "NO_VERSION_FOUND", "software_name": exact_name}
        
    detected_version = version_match.group(0)
    
    # Pull matching CVE structural vectors for this precise version sequence
    query = """
        SELECT c.cve_id, c.cvss_score, c.description
        FROM releases r
        JOIN release_cve_mapping m ON r.id = m.release_id
        JOIN cves c ON m.cve_id = c.cve_id
        WHERE r.software_id = ? AND r.version = ?
        ORDER BY c.cvss_score DESC
    """
    cursor.execute(query, (sw_id, detected_version))
    cve_records = cursor.fetchall()
    
    conn.close()
    
    return {
        "status": "MATCHED",
        "software_name": exact_name,
        "detected_version": detected_version,
        "latest_version": latest_version,
        "cves": [{"cve_id": r[0], "cvss_score": r[1], "description": r[2]} for r in cve_records]
    }

# ==========================================
# 3. Nmap CLI Pipeline & Live Report Generator
# ==========================================
def run_nmap_and_generate_report(target_ip: str):
    """
    Spawns a native system subprocess running Nmap CLI.
    Parses output in real-time, outputs to terminal, and writes findings
    plus the raw Nmap log into a timestamped file.
    """
    sanitized_ip = re.sub(r'[\\/*?:"<>|]', "_", target_ip)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{sanitized_ip}-{timestamp}.txt"

    print(f"\n⚡ Spawning native subprocess: [ nmap -sV {target_ip} ]")
    print("⏳ Running service intensity discovery scan... Please stand by.\n")
    
    nmap_row_regex = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+([\w\-/\+]+)\s+(.*)$")
    
    try:
        process = subprocess.Popen(
            ["nmap", "-sV", target_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        services_found = 0
        analysis_report_lines = []
        raw_nmap_output_lines = []
        
        # Initialize Report Header metadata
        analysis_report_lines.append("="*75)
        analysis_report_lines.append(f"🛡️  VULNERABILITY ASSESSMENT REPORT (KNOWLEDGE GRAPH POWERED)")
        analysis_report_lines.append(f"📅 Scan Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        analysis_report_lines.append(f"🎯 Target Address : {target_ip}")
        analysis_report_lines.append("="*75 + "\n")
        analysis_report_lines.append("🔍 SECTION 1: KNOWLEDGE GRAPH MAPPING & REMEDIATION ANALYSIS")
        analysis_report_lines.append("-"*75)

        for line in process.stdout:
            raw_nmap_output_lines.append(line.rstrip('\n'))
            cleaned_line = line.strip()
            match = nmap_row_regex.match(cleaned_line)
            
            if match:
                services_found += 1
                port, protocol, service_type, service_info = match.groups()
                
                block = []
                block.append("="*75)
                block.append(f"🔌 MAPPED PORT: {port}/{protocol} | Service Type: {service_type.upper()}")
                block.append(f"📄 Raw Banner Info: {service_info}")
                block.append("-"*75)
                
                graph_result = query_knowledge_graph(service_info)
                
                if graph_result["status"] == "NOT_ONBOARDED":
                    block.append("   ⚠️  [STATUS]: This Software is not onboarded on the Knowledge Graph.")
                    
                elif graph_result["status"] == "NO_VERSION_FOUND":
                    block.append(f"   ✅ [STATUS]: Software recognized as '{graph_result['software_name']}'")
                    block.append("   ⚠️  [VERSION]: Nmap could not cleanly parse an exact version string out of the banner.")
                    
                elif graph_result["status"] == "MATCHED":
                    block.append(f"   ✅ [STATUS]: Software recognized as '{graph_result['software_name']}'")
                    block.append(f"   🔍 [VERSION]: Extracted local version string -> [{graph_result['detected_version']}]")
                    
                    is_latest = (graph_result['detected_version'].strip() == graph_result['latest_version'].strip())
                    if is_latest:
                        block.append(f"   🟢 [REMEDIATION]: Success! Running latest stable version ({graph_result['latest_version']}).")
                    else:
                        block.append(f"   🚨 [REMEDIATION]: Outdated instance. Strongly recommend upgrading to: {graph_result['latest_version']}")
                    
                    cves = graph_result["cves"]
                    if cves:
                        block.append(f"   ❌ Found {len(cves)} vulnerability links mapped via Graph indexes:")
                        for cve in cves:
                            block.append(f"       ├── 🛑 {cve['cve_id']} (CVSS: {cve['cvss_score']}) - {cve['description']}")
                    else:
                        block.append("   🟢 No CVE vulnerabilities mapped inside local graph tables for this version context.")
                        
                block.append("="*75 + "\n")
                
                for block_line in block:
                    print(block_line)
                
                analysis_report_lines.extend(block)
                
        process.wait()
        
        if process.returncode != 0:
            err_msg = f"❌ Nmap execution encountered an unexpected CLI issue. Exit Code: {process.returncode}"
            print(err_msg)
            analysis_report_lines.append(err_msg)
        elif services_found == 0:
            no_services_msg = "🏁 Scan completed. No open application port banners were detected on target."
            print(no_services_msg)
            analysis_report_lines.append(no_services_msg)
            
        final_report_content = []
        final_report_content.extend(analysis_report_lines)
        
        final_report_content.append("\n" + "="*75)
        final_report_content.append("📝 SECTION 2: RAW NMAP COMMAND LINE OUTPUT LOGS")
        final_report_content.append("="*75)
        final_report_content.extend(raw_nmap_output_lines)
        final_report_content.append("\n" + "="*75)
        final_report_content.append("🏁 END OF ASSESSMENT REPORT")
        final_report_content.append("="*75)

        with open(report_filename, "w", encoding="utf-8") as report_file:
            report_file.write("\n".join(final_report_content))
        print(f"💾 Comprehensive report file compiled and saved successfully to: [ {report_filename} ]")
    except FileNotFoundError:
        print("❌ Error: The native 'nmap' tool was not found on your system PATH.")
    except Exception as e:
        print(f"❌ Core processing runtime error: {e}")
def main():
    print("="*75)
    print("🛡️  NATIVE CLI NMAP SCANNER + COMPREHENSIVE REPORT GENERATION")
    print("="*75)
    target_ip = input("Enter target IP address or hostname for assessment: ").strip()
    if not target_ip:
        print("❌ Target entry field cannot be empty. Shutting down scanner.")
        return
    run_nmap_and_generate_report(target_ip)
if __name__ == "__main__":
    main()
