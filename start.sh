#!/bin/bash

pkill -f "gunicorn.*0.0.0.0:3003" 2>/dev/null || true
sleep 2

gunicorn -b 0.0.0.0:3003 --preload --workers=8 --threads=20 'app:create_app()'