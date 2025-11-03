#!/usr/bin/env python3
"""
Launcher script for PangCrypter.
Run this script to start the application.
"""

import sys
import os

# Add the current directory to Python path so we can import pangcrypter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the main function
from pangcrypter.main import main

if __name__ == "__main__":
    main()
