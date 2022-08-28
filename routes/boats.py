from google.cloud import datastore
from flask import request, Blueprint
from functions.createRes import create_res
from functions.verifyJwt import verify_jwt

client = datastore.Client()

boats = Blueprint("boats", __name__)

# Create a boat if the Authorization header contains a valid JWT
# or returns all boats associated with an authenticated user
@boats.route('', methods=['POST', 'GET'])
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

# Various interactions with boat data entities. Requires valid Authorization
@boats.route('/<id>', methods=['DELETE', 'GET', 'PATCH', 'PUT'])
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


# Boat/load interaction 
@boats.route('/<bid>/loads/<lid>', methods=['PUT','DELETE'])
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