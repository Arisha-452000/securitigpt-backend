#!/bin/bash
# Render deployment start script

# Set environment variables for production
export PYTHONPATH=/opt/render/project/src/backend:$PYTHONPATH

# Start the FastAPI application
cd /opt/render/project/src/backend
python render_start.py
