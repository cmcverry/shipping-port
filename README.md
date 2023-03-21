# Shipping Port

Shipping Port is a REST API that allows users to manipulate digital representations of ships and carried cargo. Interactions with the API occur via HTTP requests made to the API’s various endpoints. A user who has authenticated with the API can freely create their own boats, loads, and perform interactions between the two related data entities.  

## Instructions: 

Web URL: https://shipping-port-6543.ue.r.appspot.com/ 

To authenticate with the API, a user must visit the authentication page. Upon clicking login, a user is redirected to an Auth0 authentication page. The API’s authentication is handled by Auth0, a 3rd party authentication service. A user can either choose to authenticate with a Auth0 or Google account. Note: By authenticating with a Google account, a user shares their name, email address, language preference, and profile picture with Auth0.

Upon authenticating, a user is redirected to an info page containing the user’s name, a unique ID that the API uses to identify the user, and a JSON Web Token (JWT). Now, a user is ready to start interacting with the API. 

All HTTP requests made to the API that interact with boat entities require an Authorization header containing ‘Bearer [user’s unique JWT]’. Examples of HTTP requests can be found in provided Postman JSON files. JWTs do expire after a set period of time, after which they become invalid. A user must visit the authentication page whenever they need a new valid JWT. Alternatively, a user who has previously authenticated with the API using an Auth0 account can retrieve a new valid JWT via a HTTP request to the API. 

For details about the API specifications, endpoints, and accepted HTTP requests visit [API Specifications](https://github.com/cmcverry/shippingPort/blob/main/documentation/shipping-port.pdf). 

For examples of valid and invalid requests made over Postman, checkout the Postman JSON files [Full Documentation](https://github.com/cmcverry/shippingPort/tree/main/documentation).
