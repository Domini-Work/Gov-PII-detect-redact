"""
Pytest configuration ensuring repository root is always on sys.path.
"""

import sys
import os

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
