from google.cloud import datastore
from flask import request, Blueprint
from functions.createRes import create_res


client = datastore.Client()
loads = Blueprint("loads", __name__)

# Creates a load data entity or returns all existing loads
@loads.route('', methods=['POST', 'GET'])
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

# Various interactions with load data entities
@loads.route('/<id>', methods=['DELETE', 'GET', 'PATCH', 'PUT'])
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