# HAProxy VPN Monitor Dashboard

A modern, real-time monitoring dashboard for HAProxy-based VPN failover systems with automatic server switching capabilities.

## 🚀 Features

- **Real-time Monitoring**: Live status updates every 5 seconds
- **Automatic Failover**: Seamless switching between VPN servers
- **Modern UI**: Beautiful, responsive dashboard with dark theme
- **Multi-Server Support**: Monitor WireGuard, IPSec, and IPIP tunnels
- **Traffic Statistics**: View bandwidth usage and connection counts
- **Secure Access**: Built-in authentication system
- **Lightweight**: Minimal resource usage


### Login Page
- Clean and modern authentication interface
- Secure session management

### Dashboard
- Real-time server status
- Active connections monitoring
- Traffic statistics
- Automatic failover indication

## 🛠️ Requirements

- HAProxy 2.0+
- Python 3.6+
- Flask
- socat

## 📦 Installation

### 1. Clone the repository
```bash
git clone https://github.com/soheilas/HAProxy-VPN-Monitor.git
cd HAProxy-VPN-Monitor
```

### 2. Install dependencies
```bash
apt update
apt install python3 python3-pip haproxy socat -y
pip3 install flask flask-cors
```

### 3. Configure HAProxy
Add this configuration to `/etc/haproxy/haproxy.cfg`:

```cfg
frontend at
    bind :::1010
    bind *:1010
    mode tcp
    option tcplog
    timeout client 300s
    default_backend at

backend at
    mode tcp
    option tcp-check
    tcp-check connect
    option redispatch
    retries 3
    timeout connect 500ms
    timeout server 300s
    timeout check 500ms
    
    server WireGuard 10.100.3.2:1010 check inter 200ms fall 1 rise 2
    server OpenVPN 10.100.2.2:1010 check backup inter 200ms fall 1 rise 2
    server V2ray 10.100.1.2:1010 check backup inter 200ms fall 1 rise 2
```

### 4. Configure the monitoring script
Edit `ha-api.py` and set your credentials:
```python
ADMIN_USERNAME = 'soheil'
ADMIN_PASSWORD = 'star'
```

### 5. Create systemd service
```bash
cat > /etc/systemd/system/ha-monitor.service << EOF
[Unit]
Description=HaPorxy Monitor Dashboard
After=network.target haproxy.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt
ExecStart=/usr/bin/python3 /opt/vpn-api.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable ha-monitor
systemctl start ha-monitor
```

## 🔧 Configuration

### Server Configuration
Modify the server list in `vpn-api.py`:
```python
servers = [
    { name: 'WireGuard', type: 'Primary', id: 'WireGuard' },
    { name: 'OpenVPN', type: 'Backup', id: 'OpenVPN' },
    { name: 'V2ray', type: 'Backup', id: 'V2ray' }
]
```

### Refresh Interval
Change the update frequency (default: 5 seconds):
```javascript
setInterval(fetchStats, 5000);  // milliseconds
```

## 🌐 Usage

1. Access the dashboard at `http://your-server-ip:5000`
2. Login with your configured credentials
3. Monitor your VPN servers in real-time
4. The system automatically switches to backup servers when the primary fails

## 🔒 Security

- Password-protected access
- Session-based authentication
- Support for IP whitelisting
- Optional HTTPS support

## 📊 API Endpoints

- `GET /` - Main dashboard (requires authentication)
- `GET /api/stats` - JSON statistics (requires authentication)
- `POST /login` - Authentication endpoint
- `GET /logout` - Logout endpoint


---
