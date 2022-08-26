# Shipping Port

Shipping Port is a REST API that allows users to interact wit and manipulate two related data entities boats and loads. Interaction with the API occurs via HTTP requests made to the app’s various endpoints. A user who has authenticated with the API can freely create their own boats, loads, and perform interactions between the two data entities.  

## Instructions: 

To authenticate with the API, a user must visit https://shipping-port-6543.ue.r.appspot.com/ and click the login link. Upon clicking login, a user is redirected to an Auth0 authentication page. The API’s authentication is handled by Auth0, a 3rd party authentication/authorization service. A user can either choose to authenticate with a Auth0 or Google account. Note: By authenticating with a Google account, the user shares their name, email address, language preference, and profile picture with Auth0. Upon authenticating, a user is redirected to an info page containing the user’s name, a unique ID that that the API will use to identify the user, and a JavaScript Web Token (JWT) string. Now a user is ready to start interacting with the API. All HTTP requests that interact with boat entities require an Authorization header containing ‘Bearer [user’s JWT]’. Examples of HTTP requests can be found in provided Postman JSON files. JWTs do have an expiration, after which they become invalid. A user must visit https://shipping-port-6543.ue.r.appspot.com/ whenever they need a new valid JWT. Alternatively, a user who has previously authenticated with API can make retrieve a new valid JWT via a HTTP request. 

For details about the API specifications, endpoints, and accepted HTTP requests visit [API Specifications](https://github.com/cmcverry/shippingPort/blob/main/documentation/shipping-port.pdf). 

For examples of valid and invalid requests made over Postman, checkout the Postman JSON files [Full Documentation](https://github.com/cmcverry/shippingPort/tree/main/documentation).
