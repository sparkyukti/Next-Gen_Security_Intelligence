import sqlite3
import os

DB_FILE = "cve_knowledge_graph.db"

def inspect_database():
    if not os.path.exists(DB_FILE):
        print(f"❌ Error: Database file '{DB_FILE}' not found in the current directory.")
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    print("\n" + "="*50)
    print("📊 KNOWLEDGE GRAPH SCHEMA & AUDIT REPORT")
    print("="*50)
    
    # 1. Check Row Counts across Graph Nodes & Edges
    tables = ['software', 'releases', 'cves', 'release_cve_mapping']
    for table in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"🔹 Table '{table:<20}': {count} entries")
        except sqlite3.OperationalError:
            print(f"❌ Table '{table}' does not exist or has a faulty format!")

    print("\n" + "="*50)
    print("🧠 HUMAN-READABLE KNOWLEDGE GRAPH DUMP")
    print("="*50)

    # 2. Complete Graph Traversal Query via Joins
    graph_query = """
        SELECT 
            s.name AS software_name, 
            s.latest_version AS current_version, 
            r.version AS release_version, 
            c.cve_id, 
            c.cvss_score, 
            c.description
        FROM software s
        LEFT JOIN releases r ON s.id = r.software_id
        LEFT JOIN release_cve_mapping m ON r.id = m.release_id
        LEFT JOIN cves c ON m.cve_id = c.cve_id
        ORDER BY s.name ASC, r.version DESC, c.cvss_score DESC
    """
    
    try:
        cursor.execute(graph_query)
        rows = cursor.fetchall()
        
        if not rows:
            print("⚠️ The database is structured correctly, but it contains no records yet.")
            return

        current_sw = ""
        current_ver = ""
        
        for row in rows:
            sw_name, latest_ver, rel_ver, cve_id, cvss, desc = row
            
            # Print Software Node Grouping
            if sw_name != current_sw:
                print(f"\n🖥️  SOFTWARE NODE: {sw_name.upper()} (Latest Known: {latest_ver})")
                current_sw = sw_name
                current_ver = "" # Reset version tracker for the new software
                
            # Print Release Node Grouping
            if rel_ver and rel_ver != current_ver:
                print(f"   └── 📦 Release Version: {rel_ver}")
                current_ver = rel_ver
                
            # Print Connected CVE Edge Nodes
            if cve_id:
                print(f"       └── 🛑 [{cve_id}] | CVSS: {cvss:<4} | {desc}")
            else:
                print("       └── 🟢 No known CVE vulnerabilities recorded for this version.")
                
    except Exception as e:
        print(f"❌ Failed to run Graph Traversal query: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    inspect_database()
