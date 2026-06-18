import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime

# Get database URL from environment variable
DATABASE_URL = os.getenv('DATABASE_URL')

def get_db_connection():
    """Create a connection to PostgreSQL database"""
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable not set!")
    
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    return conn

def init_db():
    """Create tables if they don't exist"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Create scans table (matching your schema)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            target_url TEXT,
            modules TEXT,
            pages_crawled INTEGER,
            scan_duration TEXT,
            vulnerabilities_found INTEGER,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create findings table (matching your schema)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER REFERENCES scans(id),
            type TEXT,
            url TEXT,
            parameter TEXT,
            severity TEXT,
            method TEXT
        )
    """)
    
    cur.close()
    conn.close()
    print("✅ Database tables created/verified successfully!")

def save_scan(target_url, modules, pages_crawled, scan_duration, vulnerabilities_found):
    """Save a new scan and return its ID"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("""
        INSERT INTO scans (target_url, modules, pages_crawled, scan_duration, vulnerabilities_found, scanned_at)
        VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        RETURNING id
    """, (target_url, modules, pages_crawled, scan_duration, vulnerabilities_found))
    
    scan_id = cur.fetchone()[0]
    
    cur.close()
    conn.close()
    return scan_id

def get_history():
    """Get last 10 scans ordered by date"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 10")
    rows = cur.fetchall()
    
    cur.close()
    conn.close()
    return rows

def save_findings(scan_id, vulnerabilities):
    """Save vulnerability findings for a scan"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    for vuln in vulnerabilities:
        cur.execute("""
            INSERT INTO findings (scan_id, type, url, parameter, severity, method)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (scan_id, vuln["type"], vuln["url"], vuln["parameter"], vuln["severity"], vuln["method"]))
    
    cur.close()
    conn.close()

def get_scan_findings(scan_id):
    """Get all findings for a specific scan"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("SELECT * FROM findings WHERE scan_id = %s", (scan_id,))
    rows = cur.fetchall()
    
    cur.close()
    conn.close()
    return rows

def get_analytics_data():
    """Get data for dashboard charts"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Total scans
    cur.execute("SELECT COUNT(*) as total_scans FROM scans")
    total_scans = cur.fetchone()['total_scans']
    
    # Vulnerabilities by severity
    cur.execute("""
        SELECT severity, COUNT(*) as count 
        FROM findings 
        WHERE severity IS NOT NULL
        GROUP BY severity
    """)
    severity_data = cur.fetchall()
    
    # Vulnerabilities by type
    cur.execute("""
        SELECT type, COUNT(*) as count 
        FROM findings 
        WHERE type IS NOT NULL
        GROUP BY type 
        ORDER BY count DESC 
        LIMIT 10
    """)
    type_data = cur.fetchall()
    
    # Scans over time (last 7 days)
    cur.execute("""
        SELECT DATE(scanned_at) as date, COUNT(*) as count 
        FROM scans 
        WHERE scanned_at >= CURRENT_DATE - INTERVAL '7 days'
        GROUP BY DATE(scanned_at)
        ORDER BY date ASC
    """)
    timeline_data = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return {
        'total_scans': total_scans,
        'severity_distribution': severity_data,
        'vulnerability_types': type_data,
        'timeline': timeline_data
    }

def get_scan_by_id(scan_id):
    """Get a specific scan by ID with its findings"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
    scan = cur.fetchone()
    
    if scan:
        cur.execute("SELECT * FROM findings WHERE scan_id = %s", (scan_id,))
        findings = cur.fetchall()
        scan['findings'] = findings
    
    cur.close()
    conn.close()
    return scan

# Run init when module is imported
init_db()