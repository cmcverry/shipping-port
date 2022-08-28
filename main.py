from google.cloud import datastore
from flask import Flask, redirect, render_template, session, url_for
from authlib.integrations.flask_client import OAuth
from routes import boats, loads, users, login
from credentials.secrets import SECRET, AUTH0_ID, AUTH0_SECRET, DOMAIN


app = Flask(__name__)
app.secret_key = SECRET
app.register_blueprint(boats.boats, url_prefix="/boats")
app.register_blueprint(loads.loads, url_prefix="/loads")
app.register_blueprint(users.users, url_prefix="/users")
app.register_blueprint(login.login, url_prefix="/login")

client = datastore.Client()

oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_ID,
    client_secret=AUTH0_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://' + DOMAIN + '/.well-known/openid-configuration'
)

# Routes for authentication on web
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/weblogin')
def redirect_login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()

    query = client.query(kind="users")
    query.add_filter("user_id", "=", token['userinfo']["sub"])
    results = list(query.fetch())
    
    if not results:
        new_user = datastore.entity.Entity(key=client.key("users"))
        new_user.update({"user_id": token['userinfo']['sub'], "name": token["userinfo"]["name"], "boats": []})
        client.put(new_user)

    session["user"] = token
    return redirect("/info")

@app.route("/info")
def info():
    return render_template("info.html", session=session.get('user'))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

