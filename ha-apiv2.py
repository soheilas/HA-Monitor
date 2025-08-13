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
ADMIN_PASSWORD = 'star'

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

def detect_server_type(server_name):
    """تشخیص نوع سرور بر اساس نام"""
    name_lower = server_name.lower()
    
    if 'wg' in name_lower or 'wireguard' in name_lower:
        return {'type': 'WireGuard', 'icon': '🔐', 'priority': 1}
    elif 'ipsec' in name_lower or 'esp' in name_lower:
        return {'type': 'IPSec', 'icon': '🛡️', 'priority': 2}
    elif 'vxlan' in name_lower:
        return {'type': 'VXLAN', 'icon': '🌐', 'priority': 3}
    elif 'openvpn' in name_lower or 'ovpn' in name_lower:
        return {'type': 'OpenVPN', 'icon': '🔒', 'priority': 4}
    elif 'v2ray' in name_lower or 'vmess' in name_lower:
        return {'type': 'V2Ray', 'icon': '⚡', 'priority': 5}
    elif 'shadowsocks' in name_lower or 'ss' in name_lower:
        return {'type': 'Shadowsocks', 'icon': '👤', 'priority': 6}
    else:
        return {'type': 'Unknown', 'icon': '❓', 'priority': 99}

def detect_location(server_name):
    """تشخیص موقعیت جغرافیایی سرور"""
    name_lower = server_name.lower()
    
    if 'de' in name_lower or 'germany' in name_lower or 'german' in name_lower:
        return {'location': 'آلمان', 'flag': '🇩🇪'}
    elif 'fl' in name_lower or 'finland' in name_lower or 'finnish' in name_lower:
        return {'location': 'فنلاند', 'flag': '🇫🇮'}
    elif 'us' in name_lower or 'usa' in name_lower or 'america' in name_lower:
        return {'location': 'آمریکا', 'flag': '🇺🇸'}
    elif 'uk' in name_lower or 'britain' in name_lower or 'england' in name_lower:
        return {'location': 'انگلستان', 'flag': '🇬🇧'}
    elif 'fr' in name_lower or 'france' in name_lower:
        return {'location': 'فرانسه', 'flag': '🇫🇷'}
    elif 'nl' in name_lower or 'netherlands' in name_lower or 'holland' in name_lower:
        return {'location': 'هلند', 'flag': '🇳🇱'}
    else:
        return {'location': 'نامشخص', 'flag': '🌍'}

def get_haproxy_stats():
    """دریافت آمار از HAProxy - اصلاح نهایی"""
    try:
        cmd = f'echo "show stat" | socat stdio {HAPROXY_SOCKET}'
        print(f"[DEBUG] Running command: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        print(f"[DEBUG] Return code: {result.returncode}")
        print(f"[DEBUG] Output length: {len(result.stdout)}")
        
        if result.returncode != 0:
            print(f"[ERROR] Command failed: {result.stderr}")
            return None
        
        # حذف # از ابتدای header
        csv_data = result.stdout.replace('# pxname', 'pxname')
        print(f"[DEBUG] CSV data first line: {csv_data.split(chr(10))[0][:100]}...")
        
        stats = {}
        reader = csv.DictReader(io.StringIO(csv_data))
        
        # چاپ فیلدهای موجود
        print(f"[DEBUG] CSV fieldnames: {reader.fieldnames[:10] if reader.fieldnames else 'None'}...")
        
        for row in reader:
            # فقط server ها را در نظر بگیریم (نه frontend/backend)
            svname = row.get('svname', '')
            if svname and svname not in ['FRONTEND', 'BACKEND']:
                server_name = svname
                print(f"[DEBUG] Processing server: {server_name}")
                
                # اطلاعات تشخیص خودکار
                server_type_info = detect_server_type(server_name)
                location_info = detect_location(server_name)
                
                # ساخت آمار با safe access
                stats[server_name] = {
                    'status': row.get('status', 'UNKNOWN'),
                    'current_sessions': int(row.get('scur', '0') or '0'),
                    'total_sessions': int(row.get('stot', '0') or '0'),
                    'bytes_in': int(row.get('bin', '0') or '0'),
                    'bytes_out': int(row.get('bout', '0') or '0'),
                    'check_status': row.get('check_status', 'N/A'),
                    'active': row.get('act', '0') == '1',
                    'backup': row.get('bck', '0') == '1',
                    'weight': int(row.get('weight', '0') or '0'),
                    'backend': row.get('pxname', 'Unknown'),
                    
                    # اطلاعات تشخیص شده
                    'type': server_type_info['type'],
                    'icon': server_type_info['icon'],
                    'priority': server_type_info['priority'],
                    'location': location_info['location'],
                    'flag': location_info['flag'],
                    
                    # لیبل ترکیبی
                    'display_name': f"{location_info['flag']} {server_type_info['icon']} {server_name}",
                    'full_label': f"{location_info['location']} - {server_type_info['type']}"
                }
                
                print(f"[DEBUG] Added server {server_name}: status={stats[server_name]['status']}, sessions={stats[server_name]['current_sessions']}")
        
        print(f"[DEBUG] Total servers found: {len(stats)}")
        return stats
        
    except Exception as e:
        print(f"[ERROR] Exception in get_haproxy_stats: {e}")
        import traceback
        traceback.print_exc()
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
        <h2>ورود به پنل مانیتورینگ</h2>
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
    """API endpoint برای دریافت آمار - کاملاً dynamic"""
    print("[DEBUG] API /api/stats called")
    stats = get_haproxy_stats()
    
    if stats is None:
        print("[ERROR] Could not fetch HAProxy stats")
        return jsonify({'error': 'Could not fetch HAProxy stats'}), 500
        
    total_servers = len(stats)
    active_servers = sum(1 for s in stats.values() if s['status'] == 'UP')
    total_connections = sum(s['current_sessions'] for s in stats.values())
    total_traffic = sum(s['bytes_in'] + s['bytes_out'] for s in stats.values())
    
    # پیدا کردن سرور فعال (که دارد ترافیک handle می‌کند)
    active_server = None
    backup_servers = []
    
    for name, data in stats.items():
        if data['status'] == 'UP' and data['active'] and data['current_sessions'] > 0:
            active_server = name
        elif data['backup'] and data['status'] == 'UP':
            backup_servers.append(name)
    
    # اگر سرور فعال نداشتیم، اولین سرور UP را انتخاب کن
    if not active_server:
        for name, data in stats.items():
            if data['status'] == 'UP' and data['active']:
                active_server = name
                break
    
    # مرتب کردن سرورها بر اساس priority و وضعیت
    sorted_servers = sorted(
        stats.items(), 
        key=lambda x: (x[1]['priority'], not x[1]['active'], x[1]['status'] != 'UP')
    )
    
    result = {
        'stats': dict(sorted_servers),
        'summary': {
            'total_servers': total_servers,
            'active_servers': active_servers,
            'total_connections': total_connections,
            'total_traffic': total_traffic,
            'active_server': active_server,
            'backup_servers': backup_servers
        }
    }
    
    print(f"[DEBUG] API response: {len(result['stats'])} servers, active: {active_server}")
    return jsonify(result)

@app.route('/')
@login_required
def dashboard():
    """نمایش داشبورد - کاملاً dynamic"""
    return '''
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HA Status Monitor - Dynamic</title>
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
            z-index: 1000;
        }

        .logout-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
        }

        .container {
            width: 100%;
            max-width: 1400px;
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
            background: linear-gradient(45deg, #4ade80, #22d3ee);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .servers-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 100px;
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
            background: rgba(74, 222, 128, 0.1);
        }

        .server-card.backup {
            border: 2px solid #fbbf24;
            box-shadow: 0 0 20px rgba(251, 191, 36, 0.2);
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

        .server-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
        }

        .server-name {
            font-size: 1.3em;
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .server-labels {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .server-type {
            font-size: 0.8em;
            background: rgba(255,255,255,0.2);
            padding: 3px 8px;
            border-radius: 8px;
            text-align: center;
        }

        .server-location {
            font-size: 0.7em;
            background: rgba(74, 222, 128, 0.2);
            padding: 2px 6px;
            border-radius: 6px;
            text-align: center;
        }

        .active-indicator {
            background: #4ade80;
            color: #1e3c72;
            padding: 4px 8px;
            border-radius: 10px;
            font-size: 0.7em;
            font-weight: bold;
            animation: pulse 1s infinite;
        }

        .backup-indicator {
            background: #fbbf24;
            color: #1e3c72;
            padding: 4px 8px;
            border-radius: 10px;
            font-size: 0.7em;
            font-weight: bold;
        }

        .server-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }

        .info-item {
            background: rgba(255,255,255,0.05);
            padding: 10px;
            border-radius: 8px;
            text-align: center;
        }

        .info-label {
            font-size: 0.8em;
            opacity: 0.8;
            margin-bottom: 5px;
        }

        .info-value {
            font-size: 1.1em;
            font-weight: bold;
        }

        .connection-label {
            background: linear-gradient(45deg, #8b5cf6, #ec4899);
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.7em;
            margin-right: 5px;
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
            z-index: 1000;
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
            z-index: 1000;
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

        .no-servers {
            text-align: center;
            padding: 50px;
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
    </style>
</head>
<body>
    <a href="/logout" class="logout-btn">🚪 خروج</a>
    
    <div class="container">
        <h1>🌐 مانیتور وضعیت سرور ها (Dynamic)</h1>
        
        <div class="stats-overview">
            <div class="stat-card">
                <div>کل سرورها</div>
                <div class="stat-number" id="total-servers">0</div>
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
            <div class="no-servers">
                <div class="loading"></div>
                <p>در حال بارگذاری اطلاعات سرورها...</p>
            </div>
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

        async function fetchStats() {
            const refreshBtn = document.getElementById('refresh-text');
            refreshBtn.innerHTML = '<div class="loading"></div>';
            
            try {
                const response = await fetch(HAPROXY_STATS_URL);
                if (response.status === 401) {
                    window.location.href = '/login';
                    return;
                }
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                const data = await response.json();
                updateUI(data);
            } catch (error) {
                console.error('Error:', error);
                showError('خطا در دریافت اطلاعات سرور: ' + error.message);
            } finally {
                refreshBtn.innerHTML = '🔄 بروزرسانی';
                updateLastUpdateTime();
            }
        }

        function updateUI(data) {
            const { stats, summary } = data;
            
            // بروزرسانی آمار کلی
            document.getElementById('total-servers').textContent = summary.total_servers;
            document.getElementById('active-servers').textContent = summary.active_servers;
            document.getElementById('active-connections').textContent = summary.total_connections;
            document.getElementById('total-traffic').textContent = formatBytes(summary.total_traffic);
            
            const container = document.getElementById('servers-container');
            container.innerHTML = '';
            
            if (Object.keys(stats).length === 0) {
                container.innerHTML = `
                    <div class="no-servers">
                        <h3>❌ هیچ سروری یافت نشد</h3>
                        <p>HAProxy در حال حاضر هیچ سرور فعالی ندارد</p>
                    </div>
                `;
                return;
            }
            
            Object.entries(stats).forEach(([serverName, serverStats]) => {
                const serverCard = createServerCard(serverName, serverStats, summary.active_server);
                container.appendChild(serverCard);
            });
        }

        function createServerCard(serverName, stats, activeServer) {
            const isOnline = stats.status === 'UP';
            const isActive = serverName === activeServer;
            const isBackup = stats.backup;
            
            const card = document.createElement('div');
            card.className = `server-card ${isActive ? 'active' : ''} ${isBackup ? 'backup' : ''}`;
            
            // لیبل کانکشن
            let connectionLabel = '';
            if (stats.current_sessions > 0) {
                connectionLabel = `<span class="connection-label">🔗 ${stats.current_sessions} فعال</span>`;
            }
            
            card.innerHTML = `
                <div class="server-status ${isOnline ? 'status-online' : 'status-offline'}"></div>
                
                <div class="server-header">
                    <div>
                        <div class="server-name">
                            ${stats.display_name}
                            ${connectionLabel}
                        </div>
                        <div style="margin-top: 8px; font-size: 0.9em; opacity: 0.8;">
                            ${stats.full_label}
                        </div>
                    </div>
                    <div class="server-labels">
                        <div class="server-type">${stats.type}</div>
                        <div class="server-location">${stats.location}</div>
                        ${isActive ? '<div class="active-indicator">🎯 فعال</div>' : ''}
                        ${isBackup ? '<div class="backup-indicator">🔄 پشتیبان</div>' : ''}
                    </div>
                </div>
                
                <div class="server-info">
                    <div class="info-item">
                        <div class="info-label">وضعیت</div>
                        <div class="info-value">${isOnline ? '✅ آنلاین' : '❌ آفلاین'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">کانکشن‌های فعال</div>
                        <div class="info-value">${stats.current_sessions}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">کل جلسات</div>
                        <div class="info-value">${stats.total_sessions.toLocaleString()}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">وزن سرور</div>
                        <div class="info-value">${stats.weight}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">ترافیک ورودی</div>
                        <div class="info-value">${formatBytes(stats.bytes_in)}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">ترافیک خروجی</div>
                        <div class="info-value">${formatBytes(stats.bytes_out)}</div>
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

        function showError(message) {
            const container = document.getElementById('servers-container');
            container.innerHTML = `
                <div class="no-servers">
                    <h3>⚠️ ${message}</h3>
                    <p>لطفاً مجدداً تلاش کنید</p>
                </div>
            `;
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
    app.run(host='0.0.0.0', port=5000, debug=True)
