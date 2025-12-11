# 🔥 PROMETHEUS - AI-Powered Red Team Swarm

**Prometheus V9** is an advanced AI-powered penetration testing framework that orchestrates multiple specialized AI agents for comprehensive security assessments.

## 🎯 Overview

Prometheus uses AutoGen's multi-agent system to create a coordinated red team that performs reconnaissance, exploitation, and post-exploitation activities through the HexStrike security tools API.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Red Team Lead (GPT-4o)             │
│          Strategic Planning & Coordination          │
└────────────┬────────────────────────┬───────────────┘
             │                        │
     ┌───────▼────────┐      ┌───────▼────────┐
     │ Recon Specialist│      │   Exploiter    │
     │   (GPT-4o)      │      │   (GPT-4o)     │
     └───────┬────────┘      └───────┬────────┘
             │                        │
             └────────────┬───────────┘
                          │
                  ┌───────▼────────┐
                  │ Post-Exploit   │
                  │ Specialist     │
                  │   (GPT-4o)     │
                  └───────┬────────┘
                          │
                  ┌───────▼────────┐
                  │   HexStrike    │
                  │  Server (Kali) │
                  │ Security Tools │
                  └────────────────┘
```

## 🛠️ Components

### Agent Roles

1. **Red Team Lead** - Strategic mission commander with full operational context
2. **Recon Specialist** - Attack surface mapping and vulnerability discovery
3. **Exploiter** - Vulnerability exploitation and initial access
4. **Post-Exploit Specialist** - Objective completion and impact demonstration

### HexStrike Tools Integration

- **Network Scanning**: nmap, rustscan, masscan
- **Web Security**: gobuster, nuclei, sqlmap, nikto
- **Exploitation**: metasploit, msfvenom
- **Password Attacks**: hydra, john, hashcat
- **Post-Exploitation**: netexec, enum4linux, file operations

## 📋 Requirements

### Windows Client
- Python 3.8+
- AutoGen libraries
- Network connectivity to Kali server

### Kali Linux Server (HexStrike)
- HexStrike AI API Server running
- All security tools installed
- Port 8888 open for API connections

## 🚀 Installation

### 1. Clone Repository
```bash
git clone <your-repo-url>
cd prometheus
```

### 2. Install Dependencies
```bash
pip install autogen-agentchat autogen-ext[openai] requests fastmcp
```

### 3. Configure API Keys

⚠️ **IMPORTANT**: Never commit API keys to Git!

Create a configuration file:
```bash
cp prometheus-v9/redteam_swarm_v9.json prometheus-v9/redteam_swarm_v9_config.json
```

Edit `redteam_swarm_v9_config.json` and add your OpenAI API key:
```json
"api_key": "your-openai-api-key-here"
```

### 4. Configure HexStrike Server

Edit `prometheus-v9/hexstrike_prometheus.py` line 151:
```python
DEFAULT_HEXSTRIKE_SERVER = "http://YOUR_KALI_IP:8888"
```

## 💻 Usage

### Start Prometheus
```bash
cd prometheus-v9
python hexstrike_prometheus.py
```

### Run a Penetration Test
Provide target and methodology to the Red Team Lead agent.

## 🔒 Security Notes

- **API Keys**: Never commit API keys. Use environment variables or separate config files.
- **HexStrike Connection**: Ensure secure network connection between Windows and Kali.
- **Kali Firewall**: Configure UFW/iptables to allow connections on port 8888.
- **Target Authorization**: Only test systems you have explicit permission to assess.

## 📁 Project Structure

```
prometheus/
├── prometheus-v9/              # Main Prometheus V9 implementation
│   ├── redteam_swarm_v9.json   # Agent configuration (TEMPLATE - add your API key)
│   ├── hexstrike_prometheus.py # HexStrike MCP client
│   ├── baseline_methodology.md # Penetration testing methodology
│   └── redteam_swarm_v9_architecture.md
├── v7/                          # Previous versions
├── v8/
├── autogen/                     # AutoGen framework
├── hexstrike-ai/               # HexStrike integration
└── PentestGPT/                 # Additional tools

```

## 🎯 Features

- **Multi-Agent Coordination**: Specialized AI agents work together
- **Methodology-Driven**: Follows structured penetration testing approach
- **Tool Integration**: 100+ security tools via HexStrike API
- **Cross-Platform**: Windows client + Kali server architecture
- **Automated Decision Making**: AI-driven tactical decisions

## 📝 License

For authorized security testing only. Always obtain proper authorization before testing any systems.

## 🤝 Contributing

This is a personal security research project. Use responsibly.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this software.

---

**Built with ❤️ for the security community**

