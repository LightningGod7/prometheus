# 🚀 Prometheus Setup Instructions

## ✅ Git Repository Created Successfully!

Your local Git repository has been initialized with:
- ✅ API keys removed from config files
- ✅ Secure .gitignore in place
- ✅ Professional README.md
- ✅ Initial commit completed

---

## 📤 Push to GitHub

### Option 1: Create New Repository on GitHub (Recommended)

1. **Go to GitHub**: https://github.com/new

2. **Create Repository**:
   - Repository name: `prometheus` (or any name you prefer)
   - Description: "AI-Powered Red Team Swarm - Multi-Agent Penetration Testing Framework"
   - Visibility: **Private** (recommended for security tools)
   - ❌ DO NOT initialize with README, .gitignore, or license (we already have these)

3. **Push to GitHub**:
   ```bash
   cd /home/zeus/prometheus
   git remote add origin https://github.com/YOUR_USERNAME/prometheus.git
   git push -u origin main
   ```

   Or using SSH (if configured):
   ```bash
   git remote add origin git@github.com:YOUR_USERNAME/prometheus.git
   git push -u origin main
   ```

### Option 2: GitHub CLI (if installed)

```bash
cd /home/zeus/prometheus
gh repo create prometheus --private --source=. --remote=origin --push
```

---

## 🔑 IMPORTANT: Before Using Prometheus

### 1. Restore Your API Key (Local Only)

Your API key was removed from the repository for security. To use Prometheus:

```bash
cd /home/zeus/prometheus/prometheus-v9

# Edit the config and add your API key
nano redteam_swarm_v9.json

# Replace "YOUR_OPENAI_API_KEY_HERE" with your actual key
```

⚠️ **NEVER commit files with real API keys!**

### 2. Configure HexStrike Server IP

Edit `hexstrike_prometheus.py` line 151:
```python
DEFAULT_HEXSTRIKE_SERVER = "http://YOUR_KALI_IP:8888"
```

---

## 📋 Next Steps

### On Kali Linux (HexStrike Server)
1. Ensure HexStrike AI API server is running
2. Configure firewall to allow port 8888:
   ```bash
   sudo ufw allow 8888/tcp
   ```

### On Windows (Client)
1. Clone your repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/prometheus.git
   cd prometheus
   ```

2. Install dependencies:
   ```bash
   pip install autogen-agentchat autogen-ext[openai] requests fastmcp
   ```

3. Configure API key in `prometheus-v9/redteam_swarm_v9.json`

4. Update HexStrike server IP in `prometheus-v9/hexstrike_prometheus.py`

5. Test connection:
   ```bash
   curl http://YOUR_KALI_IP:8888/health
   ```

6. Run Prometheus:
   ```bash
   cd prometheus-v9
   python hexstrike_prometheus.py
   ```

---

## 🔒 Security Best Practices

1. **Keep Repository Private**: Contains penetration testing tools
2. **Never Commit Secrets**: API keys, passwords, or credentials
3. **Use Environment Variables**: For sensitive configuration
4. **VPN/Tunnel**: Secure connection between Windows and Kali
5. **Authorization**: Only test systems you have permission to assess

---

## 📊 Repository Status

```
Commit: dab9441
Branch: main
Files: 22 files, 9684+ lines
Status: Ready to push to remote
```

---

## 🆘 Troubleshooting

### Authentication Issues
If you get authentication errors when pushing:

**For HTTPS:**
```bash
git config --global credential.helper cache
# You'll be prompted for username/token
```

**For SSH:**
```bash
# Add your SSH key to GitHub
ssh-keygen -t ed25519 -C "your_email@example.com"
cat ~/.ssh/id_ed25519.pub
# Copy and add to GitHub: Settings > SSH and GPG keys
```

### Reset Remote (if needed)
```bash
git remote remove origin
git remote add origin <new-url>
```

---

**Ready to push? Follow Option 1 or 2 above!** 🚀

