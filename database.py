import sqlite3

def init_db():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT,
            modules TEXT,
            pages_crawled INTEGER,
            scan_duration TEXT,
            vulnerabilities_found INTEGER,
            scanned_at TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            type TEXT,
            url TEXT,
            parameter TEXT,
            severity TEXT,
            method TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()
    
def save_scan(target_url, modules, pages_crawled, scan_duration, vulnerabilities_found):
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (target_url, modules, pages_crawled, scan_duration, vulnerabilities_found, scanned_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
    """, (target_url, modules, pages_crawled, scan_duration, vulnerabilities_found))

    scan_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return scan_id   
    
def get_history():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 10")
    rows = cursor.fetchall()

    conn.close()
    return rows    

def save_findings(scan_id, vulnerabilities):
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    for vuln in vulnerabilities:
        cursor.execute("""
            INSERT INTO findings (scan_id, type, url, parameter, severity, method)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, vuln["type"], vuln["url"], vuln["parameter"], vuln["severity"], vuln["method"]))

    conn.commit()
    conn.close()
    
def get_scan_findings(scan_id):
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    rows = cursor.fetchall()

    conn.close()
    return rows    