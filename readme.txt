You must first start the docker desktop app.

Then, from a terminal, enter the following command to start Keycloak:
docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.2.2 start-dev

This command starts Keycloak exposed on the local port 8080 and creates an initial admin user with the username admin and password admin.

Log in to the Admin Console
http://localhost:8080/

Login page for auth0:
https://auth0.auth0.com/u/login/identifier?state=hKFo2SAtUHZJd0tDYXdPUUZKdkE0b2gwNXNWN1N5N241c1ZuaqFur3VuaXZlcnNhbC1sb2dpbqN0aWTZIFlfMzdMZFVjWmxaU1JJdDZWTUhpVHhIck5Jdy01a0doo2NpZNkgYkxSOVQ1YXI2bkZ0RE80ekVyR1hkb3FNQ000aU5aU1Y

I log in to Auth0 using my google credentials.
claude.bonnaud.action3d@gmail.com

CONFIGURATION OF THE AUTH0 IDENTITY PROVIDER IN KEYCLOAK

I am running keycloak using docker on my windows OS.
https://www.keycloak.org/getting-started/getting-started-docker

You must first start the docker desktop app.

Then, from a terminal, enter the following command to start Keycloak:
docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.2.2 start-dev

Since in ta-c, we are using keycloak server 21.1.2.4.2, you can start the keycloak version 21.1.2 with the following command:

docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:21.1.2 start-dev

This command starts Keycloak exposed on the local port 8080 and creates an initial admin user with the username admin and password admin.

Log in to the Admin Console
http://localhost:8080/

I have created a customer realm in keycloak with:
I have defined the Auth0 identity provider in the customer realm as an OpenID Connect v1.0 with the following settings:

Alias: auth0
Display Name: Auth0

Values derived or taken from the Keycloak Integration app created in auth0:

Discovery endpoint (derived from the Domain value dev-qdejy8uzphouw6cj.us.auth0.com):
https://dev-qdejy8uzphouw6cj.us.auth0.com/.well-known/openid-configuration

Client ID: JfT2zq4V575wqYTr8nJljnOLH496kPeC
Client secret: 9h1c11G5uNaioSNRkJfdZm-TxLBrxAo3FjdO5R_EwAG3mH7IC88dVUMiDsW1rL_C

Click on the Add button.



CONFIGURATION OF THE ACCOUNTING-APP IN KEYCLOAK

You can log in to the Admin Console of keycloak here
http://localhost:8080/
admin/admin

Inside the customer realm I have created the client accounting-app:
Client ID: accounting-app
Name : accounting-app
Clien authentication: checked
Standard flow: checked
Direct access grants: checked
Home URL: http://localhost:3001/accounting-software/
Valid redirect URIs:
http://localhost:3001/accounting-software/*
http://localhost:3001/accounting-software/login/oauth2/code/keycloak
https://localhost:8443/accounting-software/*
https://localhost:8443/accounting-software/login/oauth2/code/keycloak

Valid post logout redirect URIs:
http://localhost:3001/accounting-software/*
https://localhost:8443/accounting-software
https://localhost:8443/accounting-software/*

Web origins :
http://localhost:3001/accounting-software/
https://localhost:8443/accounting-software/

You can get the client secret from the Credentials tab:
BTZkfBjSGXmGhqK2Ann8PqMpC1IsUXPy

In the realm settings, under the OpenID Endpoint Configuration(http://localhost:8080/realms/customer/.well-known/openid-configuration), you have the issuer-uri:
issuer":"http://localhost:8080/realms/customer"

START the APP:
http://localhost:3001/accounting-software
https://localhost:8443/accounting-software
https://localhost:8443/accounting-software/tokens

 Generate a SSL/TLS Certificate:
 keytool -genkeypair -alias myapp -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore keystore.p12 -validity 3650

 Move the generated file keystore.p12 under the resources folder.