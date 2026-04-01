#!/bin/bash
# Render deployment start script

# Set environment variables for production
export PYTHONPATH=/opt/render/project/src/backend:$PYTHONPATH

# Start the FastAPI application
cd /opt/render/project/src/backend

# Automatically recreate admin user in case the database was wiped
python create_admin.py

python render_start.py
