from google.cloud import datastore
from flask import request, Blueprint
from functions.createRes import create_res


client = datastore.Client()
users = Blueprint("users", __name__)

# Returns all users authenticated with the app
@users.route('', methods=['GET'])
def get_users():

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