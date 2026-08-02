"""
Shared fixtures for the OSCP tool suite test suite.
"""
import sys
from pathlib import Path

# Add tools directory to path so we can import the tools
TOOLS_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(TOOLS_DIR))
