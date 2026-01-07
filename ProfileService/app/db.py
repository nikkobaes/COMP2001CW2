import os
import pyodbc
import random


def get_connection() -> pyodbc.Connection:
    server = os.getenv("DB_SERVER")
    database = os.getenv("DB_NAME")
    username = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")

    if not all([server, database, username, password]):
        raise RuntimeError(
            "Missing DB env vars. Required: DB_SERVER, DB_NAME, DB_USER, DB_PASSWORD"
        )

    conn_str = (
        "DRIVER={ODBC Driver 18 for SQL Server};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;"
    )

    return pyodbc.connect(conn_str)


def ensure_roles_table_exists():
    sql = """
    IF NOT EXISTS (
        SELECT * FROM sys.tables t
        JOIN sys.schemas s ON t.schema_id = s.schema_id
        WHERE t.name = 'UserRole' AND s.name = 'CW2'
    )
    BEGIN
        CREATE TABLE CW2.UserRole (
            Username VARCHAR(100) PRIMARY KEY,
            RoleName VARCHAR(50) NOT NULL
        );
    END
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    conn.close()


def get_role(username: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT RoleName FROM CW2.UserRole WHERE Username = ?", username)
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def set_role(username: str, role: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        IF EXISTS (SELECT 1 FROM CW2.UserRole WHERE Username = ?)
            UPDATE CW2.UserRole SET RoleName = ? WHERE Username = ?
        ELSE
            INSERT INTO CW2.UserRole (Username, RoleName) VALUES (?, ?)
    """, username, role, username, username, role)
    conn.commit()
    conn.close()


def ensure_role(username: str):
    role = get_role(username)
    if role:
        return role
    role = random.choice(["admin", "user"])
    set_role(username, role)
    return role