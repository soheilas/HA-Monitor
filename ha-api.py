#!/usr/bin/env python3
from flask import Flask, jsonify, render_template_string, request, session, redirect, url_for
from flask_cors import CORS
import subprocess
import csv
import io
import hashlib
from functools import wraps
import secrets

app = Flask(__name__)
CORS(app)


app.secret_key = secrets.token_hex(16)

# یوزر و پسورد - اینا رو عوض کن!
ADMIN_USERNAME = 'soheil'
ADMIN_PASSWORD = 'star'  # حتما عوض کن!


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

HAPROXY_SOCKET = '/run/haproxy/admin.sock'

def get_haproxy_stats():
    """دریافت آمار از HAProxy"""
    try:
        cmd = f'echo "show stat" | socat stdio {HAPROXY_SOCKET}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            return None
            
        stats = {}
        reader = csv.DictReader(io.StringIO(result.stdout))
        
        for row in reader:
            if row['svname'] in ['wireguard', 'openvpn', 'v2ray']:
                stats[row['svname']] = {
                    'status': row['status'],
                    'current_sessions': int(row['scur'] or 0),
                    'total_sessions': int(row['stot'] or 0),
                    'bytes_in': int(row['bin'] or 0),
                    'bytes_out': int(row['bout'] or 0),
                    'check_status': row['check_status'],
                    'active': row['act'] == '1',
                    'backup': row['bck'] == '1',
                }
                
        return stats
        
    except Exception as e:
        print(f"Error getting stats: {e}")
        return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            error = 'نام کاربری یا رمز عبور اشتباه است!'
    
    return '''
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود به سیستم</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        
        .login-container {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            width: 90%;
            max-width: 400px;
            border: 1px solid rgba(255,255,255,0.2);
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        
        h2 {
            text-align: center;
            margin-bottom: 30px;
            font-size: 2em;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 1.1em;
        }
        
        input {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 10px;
            background: rgba(255,255,255,0.2);
            color: #fff;
            font-size: 1em;
            transition: all 0.3s;
        }
        
        input::placeholder {
            color: rgba(255,255,255,0.7);
        }
        
        input:focus {
            outline: none;
            background: rgba(255,255,255,0.3);
            box-shadow: 0 0 10px rgba(74, 222, 128, 0.3);
        }
        
        button {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 10px;
            background: #4ade80;
            color: #1e3c72;
            font-size: 1.2em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
            margin-top: 10px;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(74, 222, 128, 0.4);
        }
        
        .error {
            background: #ef4444;
            padding: 10px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 20px;
        }
        
        .logo {
            text-align: center;
            font-size: 3em;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔐</div>
        <h2>ورود به پنل </h2>
        ''' + (f'<div class="error">{error}</div>' if error else '') + '''
        <form method="POST">
            <div class="form-group">
                <label for="username">نام کاربری</label>
                <input type="text" id="username" name="username" placeholder="admin" required>
            </div>
            <div class="form-group">
                <label for="password">رمز عبور</label>
                <input type="password" id="password" name="password" placeholder="••••••••" required>
            </div>
            <button type="submit">ورود</button>
        </form>
    </div>
</body>
</html>
    '''

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint برای دریافت آمار"""
    stats = get_haproxy_stats()
    
    if stats is None:
        return jsonify({'error': 'Could not fetch HAProxy stats'}), 500
        
    total_servers = len(stats)
    active_servers = sum(1 for s in stats.values() if s['status'] == 'UP')
    total_connections = sum(s['current_sessions'] for s in stats.values())
    total_traffic = sum(s['bytes_in'] + s['bytes_out'] for s in stats.values())
    
    active_server = None
    for name, data in stats.items():
        if data['status'] == 'UP' and data['active']:
            active_server = name
            break
    
    return jsonify({
        'stats': stats,
        'summary': {
            'total_servers': total_servers,
            'active_servers': active_servers,
            'total_connections': total_connections,
            'total_traffic': total_traffic,
            'active_server': active_server
        }
    })

@app.route('/')
@login_required
def dashboard():
    """نمایش داشبورد"""
    return '''
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HA Status Monitor</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 20px;
        }

        .logout-btn {
            position: fixed;
            top: 20px;
            left: 20px;
            background: #ef4444;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 20px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.3s;
        }

        .logout-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
        }

        .container {
            width: 100%;
            max-width: 1200px;
        }

        h1 {
            text-align: center;
            margin-bottom: 40px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .stats-overview {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .stat-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s;
        }

        .stat-card:hover {
            transform: translateY(-5px);
        }

        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }

        .servers-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }

        .server-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(255,255,255,0.2);
            position: relative;
            overflow: hidden;
            transition: all 0.3s;
        }

        .server-card.active {
            border: 2px solid #4ade80;
            box-shadow: 0 0 20px rgba(74, 222, 128, 0.3);
        }

        .server-status {
            position: absolute;
            top: 15px;
            left: 15px;
            width: 15px;
            height: 15px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        .status-online {
            background: #4ade80;
            box-shadow: 0 0 10px #4ade80;
        }

        .status-offline {
            background: #ef4444;
            box-shadow: 0 0 10px #ef4444;
        }

        @keyframes pulse {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.2); opacity: 0.7; }
            100% { transform: scale(1); opacity: 1; }
        }

        .server-name {
            font-size: 1.5em;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .server-type {
            font-size: 0.7em;
            background: rgba(255,255,255,0.2);
            padding: 3px 10px;
            border-radius: 10px;
        }

        .server-info {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-top: 20px;
        }

        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }

        .refresh-btn {
            position: fixed;
            bottom: 30px;
            left: 30px;
            background: #4ade80;
            color: #1e3c72;
            border: none;
            padding: 15px 30px;
            border-radius: 30px;
            font-size: 1.1em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(74, 222, 128, 0.3);
        }

        .refresh-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 6px 20px rgba(74, 222, 128, 0.5);
        }

        .last-update {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: rgba(255,255,255,0.1);
            padding: 10px 20px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <a href="/logout" class="logout-btn">🚪 خروج</a>
    
    <div class="container">
        <h1>🌐 مانیتور وضعیت سرور ها</h1>
        
        <div class="stats-overview">
            <div class="stat-card">
                <div>کل سرورها</div>
                <div class="stat-number" id="total-servers">3</div>
            </div>
            <div class="stat-card">
                <div>سرورهای فعال</div>
                <div class="stat-number" id="active-servers">0</div>
            </div>
            <div class="stat-card">
                <div>کانکشن‌های فعال</div>
                <div class="stat-number" id="active-connections">0</div>
            </div>
            <div class="stat-card">
                <div>ترافیک کل</div>
                <div class="stat-number" id="total-traffic">0 GB</div>
            </div>
        </div>

        <div class="servers-grid" id="servers-container">
            <!-- سرورها اینجا نمایش داده میشن -->
        </div>
    </div>

    <button class="refresh-btn" onclick="fetchStats()">
        <span id="refresh-text">🔄 بروزرسانی</span>
    </button>

    <div class="last-update">
        آخرین بروزرسانی: <span id="last-update">-</span>
    </div>

    <script>
        const HAPROXY_STATS_URL = '/api/stats';
        
        const servers = [
            { name: 'WireGuard', type: 'Primary', id: 'wireguard' },
            { name: 'OpenVPN', type: 'Backup', id: 'openvpn' },
            { name: 'V2RAY', type: 'Backup', id: 'v2ray' }
        ];

        async function fetchStats() {
            const refreshBtn = document.getElementById('refresh-text');
            refreshBtn.innerHTML = '<div class="loading"></div>';
            
            try {
                const response = await fetch(HAPROXY_STATS_URL);
                if (response.status === 401) {
                    window.location.href = '/login';
                    return;
                }
                const data = await response.json();
                updateUI(data);
            } catch (error) {
                console.error('Error:', error);
            } finally {
                refreshBtn.innerHTML = '🔄 بروزرسانی';
                updateLastUpdateTime();
            }
        }

        function updateUI(data) {
            const { stats, summary } = data;
            
            // بروزرسانی آمار کلی
            document.getElementById('active-servers').textContent = summary.active_servers;
            document.getElementById('active-connections').textContent = summary.total_connections;
            document.getElementById('total-traffic').textContent = formatBytes(summary.total_traffic);
            
            const container = document.getElementById('servers-container');
            container.innerHTML = '';
            
            servers.forEach((server) => {
                const serverStats = stats[server.id] || {};
                const isOnline = serverStats.status === 'UP';
                const isActive = serverStats.active;
                
                const serverCard = createServerCard(server, serverStats, isOnline, isActive);
                container.appendChild(serverCard);
            });
        }

        function createServerCard(server, stats, isOnline, isActive) {
            const card = document.createElement('div');
            card.className = `server-card ${isActive ? 'active' : ''}`;
            
            card.innerHTML = `
                <div class="server-status ${isOnline ? 'status-online' : 'status-offline'}"></div>
                <div class="server-name">
                    ${server.name}
                    <span class="server-type">${server.type}</span>
                </div>
                <div class="server-info">
                    <div class="info-row">
                        <span>وضعیت:</span>
                        <span>${isOnline ? '✅ فعال' : '❌ غیرفعال'}</span>
                    </div>
                    <div class="info-row">
                        <span>کانکشن‌ها:</span>
                        <span>${stats.current_sessions || 0}</span>
                    </div>
                    <div class="info-row">
                        <span>کل جلسات:</span>
                        <span>${stats.total_sessions || 0}</span>
                    </div>
                    <div class="info-row">
                        <span>ترافیک ورودی:</span>
                        <span>${formatBytes(stats.bytes_in || 0)}</span>
                    </div>
                    <div class="info-row">
                        <span>ترافیک خروجی:</span>
                        <span>${formatBytes(stats.bytes_out || 0)}</span>
                    </div>
                </div>
            `;
            
            return card;
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function updateLastUpdateTime() {
            const now = new Date();
            const timeStr = now.toLocaleTimeString('fa-IR');
            document.getElementById('last-update').textContent = timeStr;
        }

        // بروزرسانی خودکار هر 5 ثانیه
        setInterval(fetchStats, 5000);
        
        // بارگذاری اولیه
        fetchStats();
    </script>
</body>
</html>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)  
