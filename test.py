# test_oauth.py
import os
from flask import Flask, redirect, url_for
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')

oauth = OAuth(app)

# Google OAuth
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# GitHub OAuth
github = oauth.register(
    name='github',
    client_id=os.environ.get('GITHUB_CLIENT_ID'),
    client_secret=os.environ.get('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'}
)

@app.route('/')
def home():
    return '''
        <h2>OAuth Test</h2>
        <a href="/login/google">Login with Google</a><br>
        <a href="/login/github">Login with GitHub</a>
    '''

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('auth_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google')
def auth_google():
    try:
        token = google.authorize_access_token()
        user = google.parse_id_token(token)
        return f"<h3>Google login successful!</h3><pre>{user}</pre>"
    except Exception as e:
        return f"<h3>Google login failed!</h3><pre>{str(e)}</pre>"

@app.route('/login/github')
def login_github():
    redirect_uri = url_for('auth_github', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/auth/github')
def auth_github():
    try:
        token = github.authorize_access_token()
        resp = github.get('user', token=token)
        user_info = resp.json()
        return f"<h3>GitHub login successful!</h3><pre>{user_info}</pre>"
    except Exception as e:
        return f"<h3>GitHub login failed!</h3><pre>{str(e)}</pre>"

if __name__ == '__main__':
    app.run(debug=True)
