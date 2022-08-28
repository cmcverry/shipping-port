from flask import make_response
import json
from errorMsgs import error_messages


# Generates and returns HTTP response object using Flask's make_response method
# Receives: integer code, object body 
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

