# Policy-Driven Anonymity Controller

A Flask-based web application that provides anonymous web browsing through Tor with browser fingerprint protection. The system uses **Open Policy Agent (OPA)** with Rego policies to evaluate URL risk levels and automatically route traffic through the appropriate backend.

## 🎯 Features

- **OPA/Rego Policy Engine** - Evaluate URLs against customizable policies to determine risk levels
- **Tor Integration** - Route traffic through Tor network for anonymity
- **Browser Fingerprint Protection** - Selenium-based browsing with anti-fingerprinting measures
- **WebRTC Leak Prevention** - Prevents IP leaks through WebRTC
- **Real-time Monitoring** - Dashboard with system status, request statistics, and activity logs
- **Auto Backend Selection** - Automatically chooses Tor or Direct based on policy evaluation

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Flask Web UI  │────▶│  Policy Engine  │────▶│   OPA Server    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│ Fingerprint Mgr │────▶│  Tor Network    │
│   (Selenium)    │     │  (SOCKS5:9050)  │
└─────────────────┘     └─────────────────┘
```

## 📋 Prerequisites

- Python 3.8+
- Google Chrome browser
- Tor service running on port 9050
- OPA (Open Policy Agent) server

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/anonymity_controller.git
cd anonymity_controller
```

### 2. Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp env.example .env
# Edit .env with your configuration
```

## 🔧 Running the Application

### Step 1: Start Tor Service

Make sure Tor is running on port 9050:

```bash
# Windows: Start Tor Browser or Tor Expert Bundle
# Linux:
sudo systemctl start tor
```

### Step 2: Start OPA Server

```bash
cd anonymity_controller
opa run --server --addr :8181 opa\policies\ opa\data\
```

### Step 3: Start Flask Application

```bash
python run.py
```

The application will be available at `http://localhost:5000`

## 📁 Project Structure

```
anonymity_controller/
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── extensions.py
│   ├── models/
│   │   ├── request_log.py
│   │   └── user.py
│   ├── routes/
│   │   ├── api.py
│   │   ├── main.py
│   │   └── policy.py
│   ├── services/
│   │   ├── anonymity_service.py    # Core request processing
│   │   ├── fingerprint_manager.py  # Selenium browser management
│   │   ├── policy_engine.py        # OPA integration
│   │   └── proxy_manager.py        # Proxy configuration
│   ├── static/
│   │   ├── css/style.css
│   │   └── js/main.js
│   ├── templates/
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── monitoring.html
│   │   └── policy_config.html
│   └── utils/
│       ├── security.py
│       └── validators.py
├── opa/
│   ├── policies/
│   │   └── anonymity.rego          # Rego policy rules
│   └── data/
│       └── user_attributes.json    # Domain classifications
├── config.yaml
├── requirements.txt
├── run.py
└── README.md
```

## 🛡️ Policy Configuration

### Rego Policies

Edit `opa/policies/anonymity.rego` to customize risk evaluation rules:

```rego
package anonymity

default allow = true

risk_level = "high" {
    is_malicious_domain
}

risk_level = "low" {
    is_safe_domain
}
```

### Domain Classifications

Edit `opa/data/user_attributes.json` to add/remove domains:

```json
{
    "malicious_domains": ["example-malware.com", "phishing-site.net"],
    "safe_domains": ["google.com", "github.com", "wikipedia.org"]
}
```

## 🖥️ Usage

### Dashboard

1. Enter target URL
2. Select HTTP method (GET, POST, etc.)
3. Choose backend preference (Auto, Tor, Direct)
4. Enable/disable fingerprint protection
5. Click "Send Anonymous Request"

### Monitoring

- View real-time system status
- Track backend usage statistics
- Monitor request history and performance metrics

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| Tor Routing | All high-risk traffic routed through Tor |
| Fingerprint Protection | Anti-detection measures for browser automation |
| WebRTC Blocking | Prevents real IP leakage |
| User Agent Rotation | Randomized browser fingerprints |
| DNS over Proxy | DNS requests routed through Tor |

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard page |
| `/monitoring` | GET | Monitoring page |
| `/make-request` | POST | Submit anonymous request |
| `/system-status` | GET | Get system status |
| `/user-stats` | GET | Get user statistics |
| `/verify-tor` | GET | Verify Tor connectivity |
| `/test-connection` | POST | Test backend connection |

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `development` | Flask environment |
| `SECRET_KEY` | - | Flask secret key |
| `OPA_URL` | `http://localhost:8181` | OPA server URL |
| `TOR_SOCKS_PORT` | `9050` | Tor SOCKS5 port |

## 🐛 Troubleshooting

### OPA Connection Failed
```bash
# Check if OPA is running
curl http://localhost:8181/health
```

### Tor Not Working
```bash
# Test Tor connection
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
```

### ChromeDriver Issues
```bash
# Clear WebDriver cache
rm -rf ~/.wdm/
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📧 Contact

Your Name - kaushalramanuj10@gmail.com

Project Link: [https://github.com/kaushalramanuj/Policy-driven-Anonymity-Controller](https://github.com/kaushalramanuj/Policy-driven-Anonymity-Controller)
