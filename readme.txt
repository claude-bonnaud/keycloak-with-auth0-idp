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