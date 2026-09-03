"""Vercel Serverless Function entrypoint for FastAPI backend."""

import os
import sys

# Ensure backend package is in python search path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
BACKEND_DIR = os.path.join(PARENT_DIR, "backend")

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.main import app
