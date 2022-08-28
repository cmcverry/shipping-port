from google.cloud import secretmanager


# Retrieves secrets from the Secret Mananger API on Google Cloud for this project
# Checks authenticated Google Cloud service account's priviledges
projectID, version = 607558431758, 1
clientSecrets = secretmanager.SecretManagerServiceClient()
resource = f"projects/{projectID}/secrets/APP_SECRET/versions/{version}"
response = clientSecrets.access_secret_version(request={"name": resource})
SECRET = response.payload.data.decode("UTF-8")

resource = f"projects/{projectID}/secrets/AUTH0_CLIENT_ID/versions/{version}"
response = clientSecrets.access_secret_version(request={"name": resource})
AUTH0_ID = response.payload.data.decode("UTF-8")

resource = f"projects/{projectID}/secrets/AUTH0_CLIENT_SECRET/versions/{version}"
response = clientSecrets.access_secret_version(request={"name": resource})
AUTH0_SECRET = response.payload.data.decode("UTF-8")

DOMAIN = 'shipping-port.us.auth0.com'