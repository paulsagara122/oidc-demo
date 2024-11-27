# OIDC-Demo

## Cloning the Project

To clone this project, use the following command:

```bash
git clone https://github.com/paulsagara122/oidc-demo.git
```
## Requirements
* Java 23
* Keycloak

## Setting Up Java 23
Ensure you have Java 23 installed. You can download it from the [Amazon Corretto 23 Downloads](https://docs.aws.amazon.com/corretto/latest/corretto-23-ug/downloads-list.html) page.

## Installing Keycloak
Follow the instructions on the [Keycloak docker setup](https://www.keycloak.org/getting-started/getting-started-docker) page.

## Keycloak Configuration
1. Open the Keycloak admin console.
2. Create a new realm named __myrealm__.
3. Create a new client within this realm with the ID __my-client__.
4. Create a new user within the realm __myrealm__.
5. Copy the client secret from keycloak to __application.properties__.

For detailed Keycloak setup instructions, refer to the [Keycloak Documentation](https://www.keycloak.org/getting-started/getting-started-docker).

## Running the application
After setting up Jave and Keycloak, you can run the application using the following command:
```bash
java -jar .\target\oidc-demo-0.0.1-SNAPSHOT.jar
```
# Contributors
* [Sagar Paul](https://github.com/paulsagara122)




