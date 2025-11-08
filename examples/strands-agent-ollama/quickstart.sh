#!/bin/bash
# Quick start script for Strands Agent example

set -e

echo "=================================================="
echo "Strands Agent - OSS Compliance with Ollama"
echo "=================================================="
echo ""

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo "❌ Ollama not found!"
    echo "   Install from: https://ollama.ai"
    echo "   macOS: brew install ollama"
    exit 1
fi

echo "✅ Ollama installed"

# Check if Ollama service is running
if ! ollama list &> /dev/null; then
    echo "⚠️  Ollama service not running, starting it..."
    ollama serve &
    sleep 2
fi

echo "✅ Ollama service running"

# Check if llama3 model is available
if ! ollama list | grep -q "llama3"; then
    echo "⚠️  llama3 model not found, pulling it (this may take a few minutes)..."
    ollama pull llama3
fi

echo "✅ llama3 model available"

# Check Python version
if ! python3 --version | grep -E "Python 3\.(10|11|12|13)" &> /dev/null; then
    echo "❌ Python 3.10+ required"
    python3 --version
    exit 1
fi

echo "✅ Python 3.10+ installed"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Install mcp-semclone if not already installed
if ! python -c "import mcp_semclone" 2>/dev/null; then
    echo "📦 Installing mcp-semclone..."
    pip install -q mcp-semclone
fi

echo "✅ All dependencies installed"
echo ""
echo "=================================================="
echo "Setup complete! Ready to run the agent."
echo "=================================================="
echo ""
echo "Try these commands:"
echo ""
echo "  # Analyze a directory"
echo "  python agent.py /path/to/project"
echo ""
echo "  # Analyze with verbose output"
echo "  python agent.py /path/to/project --verbose"
echo ""
echo "  # Use a different model"
echo "  python agent.py /path/to/project --model gemma3"
echo ""
