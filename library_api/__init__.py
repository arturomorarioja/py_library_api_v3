"""
Library API
"""
__author__ = 'Arturo Mora-Rioja'
__date__ = 'October/November 2024'

import os
from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS
from library_api import database
from library_api.admin import bp_admin
from library_api.user import bp_user

load_dotenv()

def create_app():
    app = Flask(__name__)
    app.json.sort_keys = False
    CORS(app)
    app.config.from_prefixed_env()

    database.init_app(app)

    app.register_blueprint(bp_admin, url_prefix='/admin')
    app.register_blueprint(bp_user)

    print(f'### LIBRARY API ###')
    print(f'Current environment: {os.getenv("ENVIRONMENT")}')
    print(f'Using database: {app.config.get("DATABASE")}')

    return app

if __name__ == "__main__":
    create_app().run(host='0.0.0.0', port=os.getenv("PORT"))