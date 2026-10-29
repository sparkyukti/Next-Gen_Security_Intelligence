# Next-Gen_Security_Intelligence

# Next-Gen Security Intelligence

A Python-based security intelligence and vulnerability management tool that integrates local network scanning, Common Vulnerabilities and Exposures (CVE) knowledge graphs, and database utilities to analyze software assets and security risks.

## Project Structure

- **`scan_nmap.py`**: Performs network reconnaissance and scanning using Nmap to identify active hosts, open ports, and running services.
- **`generate_VulnerabilityKG.py`**: Builds and populates the vulnerability knowledge graph using collected intelligence.
- **`cve_knowledge_graph.db`**: SQLite database storing the structured CVE knowledge graph.
- **`database_info.py`**: Utility script to query, inspect, and manage the database schema and information.
- **`software_list.txt`**: Input configuration file listing the target software inventory, versions, or packages to analyze against known vulnerabilities.

## Features

- **Automated Network Scanning:** Discover network assets and services using Nmap integration.
- **Vulnerability Knowledge Graph:** Maintain a structured database (`cve_knowledge_graph.db`) mapping software components to potential CVEs.
- **Asset & Software Inventory Analysis:** Cross-reference scanned or listed software against vulnerability records.
- **Database Management Tools:** Easy inspection and management of relational security datasets via dedicated python utilities.

## Requirements

- Python 3.x
- Nmap (installed on the host system)
- Required Python libraries (depending on your specific implementation, e.g., sqlite3, python-nmap, networkx, etc.)

## Getting Started

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/sparkyukti/Next-Gen_Security_Intelligence.git](https://github.com/sparkyukti/Next-Gen_Security_Intelligence.git)
   cd Next-Gen_Security_Intelligence
