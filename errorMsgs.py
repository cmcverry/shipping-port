# Message bodies for HTTP response with error codes
error_messages = {
    401: {"Error":"Missing or invalid JWT"},
    403: {"Error":"Boat belongs to different user or (if onloading) specified load already on a boat"},
    400: {"Error" : "The request object is missing at least one of the required attributes"},
    405: {"Error": "This endpoint does not support this HTTP method"},
    406: {"Error" : "Only JSON data can be returned in response object"},
    415: {"Error" : "Only JSON deata can be accepted in request object"},
    404: {"Error" : "No resource found with the supplied resource id(s)"}
}