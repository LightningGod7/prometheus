#!/bin/bash

# Prometheus GitHub Push Script
# This script helps you push your Prometheus repository to GitHub

echo "🔥 PROMETHEUS - GitHub Repository Setup"
echo "========================================"
echo ""

# Check if we're in the right directory
if [ ! -d "/home/zeus/prometheus/.git" ]; then
    echo "❌ Error: Not in prometheus directory or git not initialized"
    exit 1
fi

cd /home/zeus/prometheus

# Check if remote already exists
if git remote | grep -q origin; then
    echo "⚠️  Remote 'origin' already exists:"
    git remote -v
    echo ""
    read -p "Do you want to remove it and add a new one? (y/N): " confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        git remote remove origin
        echo "✅ Removed existing remote"
    else
        echo "❌ Cancelled"
        exit 0
    fi
fi

echo ""
echo "📝 Please provide your GitHub repository details:"
echo ""
read -p "Enter your GitHub username: " username
read -p "Enter repository name (default: prometheus): " repo_name
repo_name=${repo_name:-prometheus}

echo ""
echo "Choose authentication method:"
echo "1) HTTPS (recommended for first-time)"
echo "2) SSH (requires SSH key setup)"
read -p "Enter choice (1 or 2): " auth_choice

if [ "$auth_choice" = "1" ]; then
    remote_url="https://github.com/${username}/${repo_name}.git"
elif [ "$auth_choice" = "2" ]; then
    remote_url="git@github.com:${username}/${repo_name}.git"
else
    echo "❌ Invalid choice"
    exit 1
fi

echo ""
echo "🔗 Adding remote: $remote_url"
git remote add origin "$remote_url"

echo ""
echo "📤 Pushing to GitHub..."
echo ""
echo "⚠️  IMPORTANT: Make sure you have created the repository on GitHub first!"
echo "   Go to: https://github.com/new"
echo "   Repository name: $repo_name"
echo "   Visibility: Private (recommended)"
echo "   Do NOT initialize with README (we already have one)"
echo ""
read -p "Press Enter when ready to push, or Ctrl+C to cancel..."

# Push to GitHub
if git push -u origin main; then
    echo ""
    echo "✅ Successfully pushed to GitHub!"
    echo ""
    echo "🌐 Your repository: https://github.com/${username}/${repo_name}"
    echo ""
    echo "📋 Next steps:"
    echo "1. On Windows: Clone the repository"
    echo "2. Install dependencies: pip install autogen-agentchat autogen-ext[openai] requests fastmcp"
    echo "3. Add your OpenAI API key to prometheus-v9/redteam_swarm_v9.json"
    echo "4. Configure HexStrike server IP in prometheus-v9/hexstrike_prometheus.py"
    echo ""
else
    echo ""
    echo "❌ Push failed!"
    echo ""
    echo "Common issues:"
    echo "1. Repository doesn't exist on GitHub - create it first"
    echo "2. Authentication failed - check credentials"
    echo "3. SSH key not configured (if using SSH)"
    echo ""
    echo "For HTTPS auth issues, try:"
    echo "  git config --global credential.helper cache"
    echo ""
    echo "For SSH setup:"
    echo "  ssh-keygen -t ed25519 -C 'your_email@example.com'"
    echo "  cat ~/.ssh/id_ed25519.pub"
    echo "  Then add the key to GitHub: Settings > SSH and GPG keys"
fi

