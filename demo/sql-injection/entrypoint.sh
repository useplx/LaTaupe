#!/bin/bash
set -e

wait-for-it.sh database:3306 -t 0 -- echo "database is ready"
python app.py migrate
python app.py loaddata collection.json
exec python app.py runserver 0.0.0.0:8000
