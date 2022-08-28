from flask import request, Blueprint
import requests
from functions.createRes import create_res
from credentials.secrets import AUTH0_ID, AUTH0_SECRET, DOMAIN


login = Blueprint("login", __name__)

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties "username" and "password"
#          of a user registered with this project's Auth0 domain
# Response: JSON body with a JWT set as the value of the property id_token
@login.route('', methods=['POST'])
def login_user():
    if request.method == 'POST':

        if "application/json" not in request.headers.get('Content-Type'):
            res = create_res(415, None)
            return res    

        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        content = request.get_json()

        if "username" not in content or "password" not in content:
            res = create_res(400, None)
            return res

        username = content["username"]
        password = content["password"]
        body = {'grant_type':'password','username':username,
                'password':password,
                'client_id':AUTH0_ID,
                'client_secret':AUTH0_SECRET
                }
        headers = { 'content-type': 'application/json' }
        url = 'https://' + DOMAIN + '/oauth/token'
        r = requests.post(url, json=body, headers=headers)
        res = create_res(200, r.text)
        return res
    
    else:
        res = create_res(405, None)
        res.headers['Access-Control-Allow-Methods'] = 'POST'
        return res