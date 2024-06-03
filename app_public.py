# Python standard libraries
import json
import os
import sqlite3
from urllib.parse import urlparse

# Third party libraries
from flask import Flask, request, redirect, session, jsonify, url_for, render_template
from flask_login import login_user, LoginManager, UserMixin, logout_user, current_user
from oauthlib.oauth2 import WebApplicationClient
import requests
import dash
from dash import Dash, html, dcc
import dash_mantine_components as dmc

# Internal imports
from db import init_db_command
from user import User
from layouts.default import layout

# Callbacks imports
import layouts.default_callbacks
import callbacks.sidebar_callbacks

# Configuration
GOOGLE_CLIENT_ID = "GOOGLE_CLIENT_ID"
GOOGLE_CLIENT_SECRET = "GOOGLE_CLIENT_SECRET"
GOOGLE_DISCOVERY_URL = (
    "GOOGLE_DISCOVERY_URL"
)

dash._dash_renderer._set_react_version('18.2.0')

stylesheets = [
    "https://unpkg.com/@mantine/dates@7/styles.css",
    "https://unpkg.com/@mantine/code-highlight@7/styles.css",
    "https://unpkg.com/@mantine/charts@7/styles.css",
    "https://unpkg.com/@mantine/carousel@7/styles.css",
    "https://unpkg.com/@mantine/notifications@7/styles.css",
    "https://unpkg.com/@mantine/nprogress@7/styles.css",
]

# Flask server setup & Dash app
server = Flask(__name__)

@server.before_request
def check_login():
    if request.method == 'GET':
        if request.path in ['/login', '/logout', '/login/callback']:
            return
        if current_user.is_authenticated:
            return
        else:
            return redirect(url_for('login'))


@server.route('/login', methods=['POST', 'GET'])
def login(message=""):
    if request.method == 'POST':
        if request.form:
            google_provider_cfg = get_google_provider_cfg()
            authorization_endpoint = google_provider_cfg["authorization_endpoint"]
            request_uri = client.prepare_request_uri(
                authorization_endpoint,
                redirect_uri=request.base_url + "/callback",
                scope=["openid", "email", "profile"],
            )
            return redirect(request_uri)
    else:
        if current_user.is_authenticated:
            return redirect('/')
    return render_template('login.html', message=message)

@server.route('/logout', methods=['GET'])
def logout():
    if current_user.is_authenticated:
        logout_user()
    return render_template('login.html', message="you have been logged out")

app = Dash(
    __name__,
    suppress_callback_exceptions=True,
    update_title=None,
    title="OAUTH PUBLIC",
    use_pages=True,
    external_stylesheets=stylesheets,
    external_scripts=['https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js'],
    server=server,
)

#app.enable_dev_tools(debug=True)

# Updating the Flask Server configuration with Secret Key to encrypt the user session cookie
server.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# Login manager object will be used to login / logout users
login_manager = LoginManager()
login_manager.init_app(server)

@login_manager.unauthorized_handler
def unauthorized():
    return "You must be logged in to access this content.", 403

# Naive database setup
try:
    init_db_command()
except sqlite3.OperationalError:
    # Assume it's already been created
    pass

# OAuth2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@server.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that we have tokens (yay) let's find and hit URL
    # from Google that gives you user's profile information,
    # including their Google Profile Image and Email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    
    # Check if email is verified
    if userinfo_response.json().get("email_verified"):
        # Get user information
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
        
        # Check if email is allowed
        allowed_emails = ["example2@example.com"]
        allowed_domains = ["gmail.com"]
        
        if users_email in allowed_emails or any(users_email.endswith(domain) for domain in allowed_domains):
            # Create a user in our db with the information provided
            # by Google
            user = User(
                id_=unique_id, name=users_name, email=users_email, profile_pic=picture
            )

            # Doesn't exist? Add to database
            if not User.get(unique_id):
                User.create(unique_id, users_name, users_email, picture)

            # Begin user session by logging the user in
            login_user(user)

            # Send user back to homepage
            return redirect(url_for("login"))
        else:
            return "Access denied. Your email is not allowed.", 403
    else:
        return "User email not available or not verified by Google.", 400

    # Doesn't exist? Add to database
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    # Begin user session by logging the user in
    login_user(user)

    # Send user back to homepage
    return redirect(url_for("login"))

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

app.layout = dmc.MantineProvider(
    dmc.AppShell(
        [
            layout,
            dmc.AppShellMain(
                [dash.page_container],
                className="content",
            ),
            dcc.Location(id='url'),
        ],
    ),
)

if __name__ == "__main__":
    server.run(ssl_context="adhoc")
    #https://127.0.0.1:5000/