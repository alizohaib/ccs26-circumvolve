#!/usr/bin/env python3
"""
Run Tests - Wrapper script that runs score_test.py for TCP/IP header manipulation evaluation.
This is the entry point called by the evaluator.
"""

import sys
import os

# Add parent directory to path to import score_test
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from score_test import run_allowed_and_blocked_tests, main

if __name__ == "__main__":
    main()

