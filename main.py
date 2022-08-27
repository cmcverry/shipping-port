from google.cloud import datastore
from flask import Flask, request, jsonify, make_response, jsonify, redirect, render_template, session, url_for
import requests
import json
from urllib.parse import urlencode
from jose import jwt
from authlib.integrations.flask_client import OAuth
from secret import secret
import os


app = Flask(__name__)
app.secret_key = os.environ['SECRET']
client = datastore.Client()

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

CLIENT_ID = os.environ['AUTH0_ID']
CLIENT_SECRET = os.environ['AUTH0_SECRET']
DOMAIN = 'shipping-port.us.auth0.com'

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://' + DOMAIN + '/.well-known/openid-configuration'
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlencode("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())

    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)

    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)

    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )

        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)
        return payload

    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

# bodies for HTTP response objects with error codes
error_messages = {
    401: {"Error":"Missing or invalid JWT"},
    403: {"Error":"Boat belongs to different user or (if onloading) specified load already on a boat"},
    400: {"Error" : "The request object is missing at least one of the required attributes"},
    405: {"Error": "This endpoint does not support this HTTP method"},
    406: {"Error" : "Only JSON data can be returned in response object"},
    415: {"Error" : "Only JSON deata can be accepted in request object"},
    404: {"Error" : "No resource found with the supplied resource id(s)"}
}

# Generates and returns HTTP response object using Flask's make_response method
# and the received argument values
# Receives arguments: integer code, object body 
# Returns: object res
def create_res(code, body):
    if not body:
        if code == 204:
            res = make_response()
        else:
            res = make_response(json.dumps(error_messages[code]))
            res.mimetype = 'application/json'
    elif body:
        res = make_response(body)
        res.mimetype = 'application/json'
    res.status_code = code
    return res


@app.route('/users', methods=['GET'])
def get_users():

    # Returns all users authenticated with the app
    if request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        query = client.query(kind="users")
        count = len(list(query.fetch()))
        results = list(query.fetch())

        counter = 1
        for e in results:
            for i in e["boats"]:
                i["self"] = request.host_url + "boats/" + str(i["id"])
            e["collection_count"] = str(counter) + ' of ' + str(count)
            counter += 1
        output = {"users": results}
        res = create_res(200, output)
        return res

    else:
        res = create_res(405, None)
        res.headers['Access-Control-Allow-Methods'] = 'GET'
        return res



# Create a boat if the Authorization header contains a valid JWT
@app.route('/boats', methods=['POST', 'GET'])
def boats_post_get():

    # Create a boat linked to user if Authorization header contains valid JWT
    if request.method == 'POST':

        try:
            payload = verify_jwt(request)
        except:
            res = create_res(401, None)
            return res

        if "application/json" not in request.headers.get('Content-Type'):
            res = create_res(415, None)
            return res
        
        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        content = request.get_json()

        if "name" not in content or "type" not in content or "length" not in content:
            res = create_res(400, None)
            return res

        new_boat = datastore.entity.Entity(key=client.key("boats"))
        new_boat.update({"name": content["name"], "type": content["type"],
          "length": content["length"], "user": payload["sub"], "loads": []})
        client.put(new_boat)

        query = client.query(kind="users")
        query.add_filter("user_id", "=", payload["sub"])
        results = list(query.fetch())
        results[0]["boats"].append({"id" : new_boat.key.id})
        client.put(results[0])

        new_boat["self"] = request.host_url + "boats/" + str(new_boat.key.id)
        new_boat["id"] = new_boat.key.id
        res = create_res(201, new_boat)
        return res

    # Returns all boats linked to a user if Authorization header contains valid JWT
    elif request.method == 'GET':
        try:
            payload = verify_jwt(request)
        except:
            res = create_res(401, None)
            return res

        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        query = client.query(kind="boats")
        query.add_filter("user", "=", payload["sub"])
        count = len(list(query.fetch()))
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        counter = q_offset + 1
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.host_url + "boats/" + str(e.key.id)
            e["collection_count"] = str(counter) + ' of ' + str(count)
            for i in e["loads"]:
                i["self"] = request.host_url + "loads/" + str(i["id"])
            counter += 1
        output = {"boats": results}
        if next_url:
            output["next"] = next_url
        res = create_res(200, output)
        return res

    else:
        res = create_res(405, None)
        res.headers['Access-Control-Allow-Methods'] = 'GET, POST'
        return res


@app.route('/boats/<id>', methods=['DELETE', 'GET', 'PATCH', 'PUT'])
def boats_get_put_patch_delete(id):

    # Returns a boat with specified boat id if Authorization header contains valid JWT
    if request.method == 'GET':
        try:
            payload = verify_jwt(request)
        except:
            res = create_res(401, None)
            return res

        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        boat_key = client.key("boats", int(id))
        boat = client.get(key=boat_key)
        
        if boat:
            if  boat["user"] != payload["sub"]:
                res = create_res(403, None)
                return res

            else:
                boat["id"] = boat.key.id
                boat["self"] = request.host_url + "boats/" + str(boat.key.id)
                for i in boat["loads"]:
                    i["self"] = request.host_url + "loads/" + str(i["id"])
                res = create_res(200, boat)
                return res
        
        else:
            res = create_res(404, None)
            return res

    # Deletes a boat with specified boat id if Authorization header contains valid JWT
    if request.method == 'DELETE':
        try:
            payload = verify_jwt(request)
        except:
            res = create_res(401, None)
            return res

        boat_key = client.key("boats", int(id))
        boat = client.get(key=boat_key)

        if boat:
            if  boat["user"] != payload["sub"]:
                res = create_res(403, None)
                return res
                
            else:
                for e in boat["loads"]:
                    load_key = client.key("loads", int(e["id"]))
                    load = client.get(key=load_key)
                    load["carrier"] = None
                    client.put(load)

                client.delete(boat_key)

                query = client.query(kind="users")
                query.add_filter("user_id", "=", payload["sub"])
                results = list(query.fetch())
                for e in results[0]["boats"]:
                    if e["id"] == boat.id:
                        results[0]["boats"].remove(e)
                        break
                client.put(results[0])

                res = create_res(204, None)
                return res
        
        else:
            res = create_res(404, None)
            return res

    # Edits and returns boat with specified boat id if Authorization header contains valid JWT
    elif request.method == 'PUT':
        try:
            payload = verify_jwt(request)
        except:
            res = create_res(401, None)
            return res

        if "application/json" not in request.headers.get('Content-Type'):
            res = create_res(415, None)
            return res    

        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        content = request.get_json()

        if "name" not in content or "type" not in content or "length" not in content:
            res = create_res(400, None)
            return res

        boat_key = client.key("boats", int(id))
        boat = client.get(key=boat_key)

        if boat:
            if  boat["user"] != payload["sub"]:
                res = create_res(403, None)
                return res
            else:
                boat.update({"name": content["name"], 
                "type": content["type"],
                "length": content["length"]})
                client.put(boat)
                boat["self"] = request.host_url + "boats/" + str(boat.key.id)
                boat["id"] = boat.key.id
                for i in boat["loads"]:
                    i["self"] = request.host_url + "loads/" + str(i["id"])
                res = create_res(200, boat)
                return res
        else:
            res = create_res(404, None)
            return res

    # Edits and returns boat with specified boat id if Authorization header contains valid JWT
    elif request.method == 'PATCH':
        try:
            payload = verify_jwt(request)
        except:
            res = create_res(401, None)
            return res

        if "application/json" not in request.headers.get('Content-Type'):
            res = create_res(415, None)
            return res    

        elif 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        content = request.get_json()

        if "name" not in content and "type" not in content and "length" not in content:
            res = create_res(400, None)
            return res

        boat_key = client.key("boats", int(id))
        boat = client.get(key=boat_key)

        if boat:
            if  boat["user"] != payload["sub"]:
                res = create_res(403, None)
                return res
            else:  
                if "name" in content:
                    boat.update({"name": content["name"]})
                if "type" in content:
                    boat.update({"type": content["type"]})
                if "length" in content:
                    boat.update({"length": content["length"]})
                client.put(boat)
                boat["self"] = request.host_url + "boats/" + str(boat.key.id)
                boat["id"] = boat.key.id
                for i in boat["loads"]:
                    i["self"] = request.host_url + "loads/" + str(i["id"])
                res = create_res(200, boat)
                return res
        else:
            res = create_res(404, None)
            return res

    else:
        res = create_res(405, None)
        res.headers['Access-Control-Allow-Methods'] = 'GET, PUT, PATCH, DELETE'
        return res


@app.route('/loads', methods=['POST', 'GET'])
def loads_post_get():

    # Creates a load
    if request.method == 'POST':

        if "application/json" not in request.headers.get('Content-Type'):
            res = create_res(415, None)
            return res
        
        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        content = request.get_json()

        if "name" not in content or "quantity" not in content or "weight" not in content:
            res = create_res(400, None)
            return res

        new_load = datastore.entity.Entity(key=client.key("loads"))
        new_load.update({"name": content["name"], "quantity": content["quantity"],
          "weight": content["weight"], "carrier": None })
        client.put(new_load)

        new_load["self"] = request.host_url + "loads/" + str(new_load.key.id)
        new_load["id"] = new_load.key.id
        res = create_res(201, new_load)
        res.status_code = 201
        return res

    # Returns all loads
    elif request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        query = client.query(kind="loads")
        count = len(list(query.fetch()))
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        counter = q_offset + 1
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.host_url + "loads/" + str(e.key.id)
            e["collection_count"] = str(counter) + ' of ' + str(count)
            if e["carrier"]:
                e["carrier"]["self"] = request.host_url + "boats/" + str(e["carrier"]["id"])
            counter += 1
        output = {"loads": results}
        if next_url:
            output["next"] = next_url
        res = create_res(200, output)
        return res

    else:
        res = create_res(405, None)
        res.headers['Access-Control-Allow-Methods'] = 'POST, GET'
        return res

@app.route('/loads/<id>', methods=['DELETE', 'GET', 'PATCH', 'PUT'])
def loads_get_put_patch_delete(id):

    # Returns load with specified load id
    if request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        load_key = client.key("loads", int(id))
        load = client.get(key=load_key)
        
        if load:
            load["id"] = load.key.id
            load["self"] = request.host_url + "loads/" + str(load.key.id)
            if load["carrier"]:
                load["carrier"]["self"] = request.host_url + "boats/" + str(load["carrier"]["id"])
            res = create_res(200, load)
            return res
        
        else:
            res = create_res(404, None)
            return res

    # Deletes load with specified id
    if request.method == 'DELETE':

        load_key = client.key("loads", int(id))
        load = client.get(key=load_key)

        if load:
            
            if load["carrier"]:
                boat_key = client.key("boats", int(load["carrier"]["id"]))
                boat = client.get(key=boat_key)
                for e in boat["loads"]:
                    if e["id"] == load.key.id:
                        boat["loads"].remove(e)
                        client.put(boat)
                        break

            client.delete(load_key)
            res = create_res(204, None)
            return res
        
        else:
            res = create_res(404, None)
            return res

    # Edits and returns load with specified id
    elif request.method == 'PUT':

        if "application/json" not in request.headers.get('Content-Type'):
            res = create_res(415, None)
            return res    

        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        content = request.get_json()

        if "name" not in content or "quantity" not in content or "weight" not in content:
            res = create_res(400, None)
            return res

        load_key = client.key("loads", int(id))
        load = client.get(key=load_key)

        if load:
            load.update({"name": content["name"], 
            "quantity": content["quantity"],
            "weight": content["weight"]})
            client.put(load)
            load["self"] = request.host_url + "loads/" + str(load.key.id)
            load["id"] = load.key.id
            if load["carrier"]:
                load["carrier"]["self"] = request.host_url + "boats/" + str(load["carrier"]["id"])
            res = create_res(200, load)
            return res

        else:
            res = create_res(404, None)
            return res

    # Edits and returns boat with specified id
    elif request.method == 'PATCH':

        if "application/json" not in request.headers.get('Content-Type'):
            res = create_res(415, None)
            return res    

        if 'application/json' not in request.accept_mimetypes:
            res = create_res(406, None)
            return res

        content = request.get_json()

        if "name" not in content and "quantity" not in content and "weight" not in content:
            res = create_res(400, None)
            return res

        load_key = client.key("loads", int(id))
        load = client.get(key=load_key)

        if load:
            if "name" in content:
                load.update({"name": content["name"]})
            if "quanity" in content:
                load.update({"quantity": content["quantity"]})
            if "weight" in content:
                load.update({"weight": content["weight"]})
            client.put(load)
            load["self"] = request.host_url + "loads/" + str(load.key.id)
            load["id"] = load.key.id
            if load["carrier"]:
                load["carrier"]["self"] = request.host_url + "boats/" + str(load["carrier"]["id"])
            res = create_res(200, load)
            return res
        else:
            res = create_res(404, None)
            return res
            
    else:
        res = create_res(405, None)
        res.headers['Access-Control-Allow-Methods'] = 'GET, PUT, PATCH, DELETE'
        return res



@app.route('/boats/<bid>/loads/<lid>', methods=['PUT','DELETE'])
def add_delete_load(bid,lid):

    # Assign a Load to a Boat
    if request.method == 'PUT':

        try:
            payload = verify_jwt(request)
        except:
            res = create_res(401, None)
            return res

        boat_key = client.key("boats", int(bid))
        boat = client.get(key=boat_key)
        load_key = client.key("loads", int(lid))
        load = client.get(key=load_key)

        if not boat or not load:
            res = create_res(404, None)
            return res

        if  boat["user"] != payload["sub"]:
            res = create_res(403, None)
            return res

        if load["carrier"]:
            res = create_res(403, None)
            return res

        load_details = {"id" : load.id}
        boat_details = {"id" : boat.id}
        boat["loads"].append(load_details)
        load["carrier"] = boat_details
        client.put(boat)
        client.put(load)
        res = create_res(204, None)
        return res

    # Remove a Load from a Boat
    if request.method == 'DELETE':
        try:
            payload = verify_jwt(request)
        except:
            res = create_res(401, None)
            return res

        boat_key = client.key("boats", int(bid))
        boat = client.get(key=boat_key)
        load_key = client.key("loads", int(lid))
        load = client.get(key=load_key)

        if not boat or not load:
            res = create_res(404, None)
            return res

        if  boat["user"] != payload["sub"]:
            res = create_res(403, None)
            return res

        for e in boat["loads"]:
            if e["id"] == load.id:
                boat['loads'].remove(e)
                load["carrier"] = None
                client.put(load)
                client.put(boat)
                res = create_res(204, None)
                return res

        res = create_res(404, None)
        return res
    
    else:
        res = create_res(405, None)
        res.headers['Access-Control-Allow-Methods'] = 'PUT, DELETE'
        return res


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


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login():
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
                'client_id':CLIENT_ID,
                'client_secret':CLIENT_SECRET
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


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

