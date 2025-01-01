# Andrvotr: service delegation plugin for Shibboleth IdP

Andrvotr allows one service to sign in to another service on behalf of the user.

The IdP administrator can define pairs of "front services" and "back services". When any *user* **U** signs in to a given *front service* **F**, the server of **F** can ask the IdP to sign in to its *back service* **B** on behalf of **U**, and send authenticated HTTP requests to the server of **B** in the name of **U**.

## Deployment requirements (limitations)

This is a list of facts that Andrvotr requires from its environment. They must be satisfied in order to successfully deploy and use Andrvotr.

- The front service and back service must be SAML Service Providers (SP). They must be connected to the same SAML Identity Provider (IdP).
- The back service must use the `HTTP-Redirect` binding for the SAML request and `HTTP-POST` for the SAML response. (This is the most common scenario.)
- The IdP must be configured to use server-side session storage.
  I.e., `idp.session.StorageService` must be set to something other than `shibboleth.ClientSessionStorageService` or `shibboleth.ClientPersistentStorageService`.
- If any "intercept" page is shown during back service sign in (e.g. attribute consent, terms of use, expiring password), the front service won't gain access.
- Direct server-to-server connections with HTTPS on port 443 must be possible. (It's only mentioned here because the base SAML protocol doesn't strictly require it.)

## Design requirements (features)

This is a list of design requirements that Andrvotr meets. In contrast to the list of limitations, they say that Andrvotr is required to work regardless of how something is configured.

- The front service and back service can be written in any language and use any SAML SP software.
- The SPs don't have to support the ECP profile or any SAML protocol extensions.
- The process is invisible to the user and the back service. They do not have to approve it or know that it happens. The IdP administrator solely decides which front services and back services are allowed to connect.
- The IdP can run on either Jetty or Tomcat.
- The IdP does not have to be a single server, it can be a cluster.
- The IdP does not have to handle mutual TLS or listen on port 8433.
- `idp.consent.StorageService` can have any configured value, it doesn't have to be server-side storage.
- The front service must not gain more privileges than necessary (e.g. signing in to any service or as any user).

## How it works

The front service receives an "Andrvotr Authority Token" from the IdP as a SAML attribute inside its SAML assertion. The token is essentially an encrypted tuple of (front service entity ID, user's IdP session cookies, expiration timestamp). It identifies a specific user accessing a specific front service at a specific point in time. It can be used to exchange SAML requests for SAML responses.

The front service then sends a login request to the back service, thus starting a normal SP-initiated SAML web flow. It follows redirects and maintains a cookie jar like real browsers. The back service responds with a HTTP redirect containing an encoded SAML request. This redirect would normally lead to the IdP's sign in form page.

Instead of following this redirect, the front service sends a special request to the IdP, asking Andrvotr to generate an artificial SAML response for this SAML request and Andrvotr Authority Token. If the request is valid and this front to back service connection is allowed, Andrvotr returns a SAML response. This is implemented with a nested request from the IdP to itself. The SAML response is just like what it would be if this user would sign into the back service directly.

The front service forwards this SAML response to the back service, receiving a session cookie and completing the sign in.

The key benefit of this design is that it requires zero changes to the back service, which just sees normal SAML flow. The cost is a moderate amount of front service complexity. If this is not a requirement you have, Andrvotr might not be the right solution for you.

<!-- TODO: Add a diagram. -->

## IdP setup

1.  Look up the latest plugin version on the [Releases page](https://github.com/fmfi-svt/andrvotr/releases).

2.  Install the plugin:

    ```shell
    /opt/shibboleth-idp/bin/plugin.sh -i https://github.com/fmfi-svt/andrvotr/releases/download/vX.Y.Z/idp-plugin-andrvotr-X.Y.Z.tar.gz
    ```

    (`-i` accepts a URL or a local path. Both `tar.gz` and `tar.gz.asc` are needed.)

3.  Edit `/opt/shibboleth-idp/conf/attribute-resolver.xml` and add this code:

    (To keep the file nicely sorted, it is suggested to insert it below the last `</AttributeDefinition>` line and above the `<!-- Data Connectors -->` line.)

    ```xml
        <AttributeDefinition id="andrvotrAuthorityToken"
                xsi:type="ContextDerivedAttribute"
                attributeValuesFunctionRef="andrvotr.AuthorityTokenGenerator">
            <AttributeEncoder xsi:type="SAML2String"
                    name="tag:fmfi-svt.github.io,2024:andrvotr-authority-token"
                    encodeType="false" />
        </AttributeDefinition>
    ```

4.  Edit `/opt/shibboleth-idp/conf/attribute-filter.xml` and add this line to the `alwaysRelease` policy:

    ```xml
            <AttributeRule attributeID="andrvotrAuthorityToken" permitAny="true" />
    ```

    Example:

    ```xml
        <AttributeFilterPolicy id="alwaysRelease">
            <PolicyRequirementRule xsi:type="ANY" />

            <AttributeRule attributeID="otherAttributeFoo" permitAny="true" />
            <AttributeRule attributeID="otherAttributeBar" permitAny="true" />
            <AttributeRule attributeID="andrvotrAuthorityToken" permitAny="true" />
        </AttributeFilterPolicy>
    ```

    (Explanation: The attribute generator only produces a value for front services, configured in the next step.
    Even though the attribute is in `alwaysRelease`, normal services won't receive it.)

5.  Look up the SP entity ID of one or more front services and back services you want to connect.

6.  Use e.g. `base64 /dev/urandom | head -c32` to generate a random "API key" for each front service.

    (Explanation: These API keys act as shared secrets between the IdP and each front service.
    Andrvotr Authority Tokens are the main authorization mechanism, but API keys exist as a simple additional precaution.)

7.  Edit `/opt/shibboleth-idp/conf/idp.properties` and add this, using your entity IDs and API keys:

    ```ini
    andrvotr.allowedConnections=[ \
        FRONT_SERVICE_1>>BACK_SERVICE_1 \
        FRONT_SERVICE_2>>BACK_SERVICE_2 \
        ... \
    ]

    andrvotr.apiKeys=[ \
        FRONT_SERVICE_1##API_KEY_1 \
        FRONT_SERVICE_2##API_KEY_2 \
        ... \
    ]
    ```

    You can change this configuration at any time.

    Entity IDs can repeat in andrvotr.allowedConnections
    (e.g. if one front service can connect to multiple back services or vice versa)
    and in andrvotr.apiKeys (e.g. to accept multiple API keys during key rotation).

    If you're worried about other users on the IdP server, you can put andrvotr.apiKeys in
    `/opt/shibboleth-idp/credentials/secrets.properties` instead of `/opt/shibboleth-idp/conf/idp.properties`.
    The only difference is chmod 600 vs 644.

8.  Restart your servlet container.

9.  Send the API keys to the developers/maintainers of your front services.

## Building from source

1.  Install [Java](https://docs.aws.amazon.com/corretto/).

2.  Install [Maven](https://maven.apache.org/install.html).

3.  ```shell
    mkdir /path/to/andrvotr-development
    cd /path/to/andrvotr-development

    git clone https://github.com/fmfi-svt/andrvotr.git

    mkdir -m700 gpgdir
    GNUPGHOME=gpgdir gpg --full-generate-key
    # Is this correct? (y/N) y
    # Real name: My test key
    # Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o
    # Leave everything else blank / default

    GNUPGHOME=gpgdir gpg --export --armor > gpgpublic.asc
    ```

4.  Build with:

    ```shell
    cd /path/to/andrvotr-development/andrvotr
    GNUPGHOME=../gpgdir MAVEN_GPG_PUBLIC_KEY="$(cat ../gpgpublic.asc)" mvn verify
    ```

    Install with:

    ```shell
    sudo -u {USER} /opt/shibboleth-idp/bin/plugin.sh -i $PWD/andrvotr-dist/target/idp-plugin-andrvotr-*-SNAPSHOT.tar.gz --noCheck
    ```

## Developing front services

Front services which want to use Andrvotr to connect to a back service must follow this procedure.

Andrvotr currently does not have a reusable client library in any language. You must implement it yourself.

You will need:

- a SAML Service Provider module or library
- an HTTP client library with cookie management
- an HTML parser library

### Login procedure

1.  Read the SAML attribute containing the Andrvotr Authority Token.
    - It is identified by `Name="tag:fmfi-svt.github.io,2024:andrvotr-authority-token"` and
      `NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"`.
    - How to read attributes depends on your SP software. In most cases it should be trivial.
    - If you use mod_shib (Shibboleth SP), it is not trivial because it discards any unknown attributes. Edit `/etc/shibboleth/attribute-map.xml` and add this:
      ```xml
      <Attribute name="tag:fmfi-svt.github.io,2024:andrvotr-authority-token" id="ANDRVOTR_AUTHORITY_TOKEN" />
      ```
    - If the IdP does not send you the attribute, the process cannot continue.
      This is most likely because the IdP is not configured correctly (andrvotr.allowedConnections, andrvotr.apiKeys).

2.  Initialize an empty cookie jar. It will be used for all HTTP requests you send.

3.  Send an HTTP request to the back service URL which initiates the login process.
    Disable automatic HTTP redirect processing in your client library.
    (If the URL is not known, use e.g. browser dev tools to see what happens when you click the login button.)

4.  Process the response to decide what request should be sent next:
    - If it is a HTTP 3xx redirect, the *next request* will be a GET of that Location header.
    - If it is a pseudo-redirect (an invisible form which is immediately submitted by JavaScript), parse the HTML page.
      The *next request* will be a POST to that form's action with the form's hidden inputs.
      Detecting this case might need some finetuning, but searching for the string "`document.forms[0].submit()`" works well in practice.
    - If it is a success page (back service specific), return success.
    - Otherwise, return failure.

5.  If the *next request* is `GET https://$your_idp/...`, instead set *next request* to `POST https://$your_idp/idp/profile/andrvotr/fabricate` with POST body parameters:
    - `front_entity_id` = the SAML SP entity ID of the front service
    - `api_key` = your Andrvotr API key (must match andrvotr.apiKeys)
    - `andrvotr_authority_token` = token from the SAML attribute
    - `target_url` = the original *next request* URL

6.  Send the *next request*.

7.  Go to step 4 to process the response.

### Example implementations

[demo/demo.py](/demo/demo.py) implements an Andrvotr client in 50 lines of Python.
It is not integrated with an SP -- you must extract the token and run demo.py manually from the command line.

```shell
./demo.py "$back_service_target_url" "$front_entity_id" "$api_key" "$andrvotr_authority_token"
```

The demo requires some Python libraries. Either [install "uv"](https://docs.astral.sh/uv/getting-started/installation/) which will take care of it. Or `apt install python3-bs4 python3-requests` and run with `python3 demo.py ...`. Or create a venv with `beautifulsoup4` and `requests`.

[Votr](https://github.com/fmfi-svt/votr/blob/master/fladgejt/login.py) contains another implementation of this procedure (also in Python).

<!-- TODO: ## Similar projects -->
