#!/usr/bin/env bash
set -e

# upgrade pip
python -m pip install --upgrade pip

# install dependencies
pip install -r requirements.txt

# run migrations
python manage.py migrate --noinput

# collect static files
python manage.py collectstatic --noinput

# exit
