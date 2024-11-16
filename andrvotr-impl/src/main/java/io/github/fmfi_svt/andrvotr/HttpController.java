package io.github.fmfi_svt.andrvotr;

import com.google.common.base.Strings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import javax.annotation.Nonnull;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.security.DataExpiredException;
import net.shibboleth.shared.security.DataSealer;
import net.shibboleth.shared.security.DataSealerException;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.slf4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/andrvotr")
public final class HttpController extends AbstractInitializableComponent {

    private final @Nonnull Logger log = LoggerFactory.getLogger(HttpController.class);

    private String idpSessionCookieName;

    private HttpClient httpClient;

    private Config config;

    private DataSealer dataSealer;

    public void setIdpSessionCookieName(@Nonnull String name) {
        checkSetterPreconditions();
        Constraint.isFalse(Strings.isNullOrEmpty(name), "idpSessionCookieName cannot be null or empty");
        idpSessionCookieName = name;
    }

    public void setHttpClient(@Nonnull HttpClient client) {
        checkSetterPreconditions();
        httpClient = Constraint.isNotNull(client, "HttpClient cannot be null");
    }

    public void setConfig(@Nonnull Config newConfig) {
        checkSetterPreconditions();
        config = Constraint.isNotNull(newConfig, "Config cannot be null");
    }

    public void setDataSealer(@Nonnull DataSealer sealer) {
        checkSetterPreconditions();
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
    }

    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (Strings.isNullOrEmpty(idpSessionCookieName)) {
            throw new ComponentInitializationException("idpSessionCookieName cannot be null or empty");
        }
        if (null == httpClient) {
            throw new ComponentInitializationException("HttpClient cannot be null");
        }
        if (null == config) {
            throw new ComponentInitializationException("Config cannot be null");
        }
        if (null == dataSealer) {
            throw new ComponentInitializationException("DataSealer cannot be null");
        }
    }

    @PostMapping("/fabricate")
    public void fabricate(@Nonnull HttpServletRequest httpRequest, @Nonnull HttpServletResponse httpResponse)
            throws IOException {
        if (!Strings.isNullOrEmpty(httpRequest.getQueryString())) {
            sendError(httpResponse, 400, "Unexpected query string");
            return;
        }

        String frontEntityID = httpRequest.getParameter("front_entity_id");
        String apiKey = httpRequest.getParameter("api_key");
        String authorityToken = httpRequest.getParameter("andrvotr_authority_token");
        String targetUrl = httpRequest.getParameter("target_url");

        if (Strings.isNullOrEmpty(frontEntityID)
                || Strings.isNullOrEmpty(apiKey)
                || Strings.isNullOrEmpty(authorityToken)
                || Strings.isNullOrEmpty(targetUrl)) {
            sendError(httpResponse, 400, "Missing required parameter");
            return;
        }

        if (!config.isValidApiKey(frontEntityID, apiKey)) {
            sendError(httpResponse, 403, "Invalid API key or front entity ID");
            return;
        }

        if (authorityToken.startsWith("E:")) {
            sendError(httpResponse, 403, "Authority token generator error: " + authorityToken);
            return;
        }
        if (!authorityToken.startsWith(Constants.AUTHORITY_TOKEN_OUTER_PREFIX)) {
            sendError(httpResponse, 403, "Invalid authority token");
            return;
        }
        String unprefixedToken = authorityToken.substring(Constants.AUTHORITY_TOKEN_OUTER_PREFIX.length());

        String plainAuthorityToken;
        try {
            plainAuthorityToken = dataSealer.unwrap(unprefixedToken);
        } catch (DataExpiredException e) {
            sendError(httpResponse, 403, "Expired authority token");
            return;
        } catch (DataSealerException e) {
            sendError(httpResponse, 403, "Invalid authority token");
            return;
        }

        // -1 because of https://errorprone.info/bugpattern/StringSplitter
        String[] parts = plainAuthorityToken.split("\n", -1);
        if (parts.length != 4
                || !Constants.AUTHORITY_TOKEN_INNER_PREFIX.equals(parts[0])
                || !frontEntityID.equals(parts[1])) {
            sendError(httpResponse, 403, "Invalid authority token");
            return;
        }

        String jsessionidCookieValue = parts[2];
        String idpSessionCookieValue = parts[3];

        String expectedPrefix = "https://" + httpRequest.getServerName() + "/idp/profile/SAML2/Redirect/SSO";
        String newPrefix = "https://" + httpRequest.getServerName() + "/idp/profile/andrvotr-internal/redirect-sso";
        if (!targetUrl.startsWith(expectedPrefix + "?")) {
            sendError(httpResponse, 403, "Invalid target URL");
            return;
        }
        String modifiedUrl = newPrefix + targetUrl.substring(expectedPrefix.length());

        String jsessionidCookieName =
                httpRequest.getServletContext().getSessionCookieConfig().getName();
        // The fallback default value is needed according to https://stackoverflow.com/q/28080813. But that could be
        // outdated, or container-dependent. In my testing with Jetty 12, getName() returned "JSESSIONID" even if
        // web.xml does not set a name.
        if (null == jsessionidCookieName) jsessionidCookieName = "JSESSIONID";

        String cookies = (jsessionidCookieName + "=" + jsessionidCookieValue) + "; "
                + (idpSessionCookieName + "=" + idpSessionCookieValue);

        // Create an internal token which certifies to the nested request's receiver that we sent it.
        String fabricationToken;
        try {
            // Expiration just for the sake of it. The exact length doesn't really matter.
            Instant expiration = Instant.now().plus(Duration.ofMinutes(10));
            fabricationToken = dataSealer.wrap("andrvotr-fabrication-token", expiration);
        } catch (Exception e) {
            log.error("DataSealer.wrap failed", e);
            sendError(httpResponse, 500, "DataSealer.wrap failed");
            return;
        }

        HttpGet nestedRequest = new HttpGet(modifiedUrl);
        nestedRequest.addHeader("Cookie", cookies);
        nestedRequest.addHeader("Andrvotr-Internal-Fabrication-Token", fabricationToken);
        nestedRequest.addHeader("Andrvotr-Internal-Fabrication-Front", frontEntityID);
        nestedRequest.addHeader("Andrvotr-Internal-Fabrication-Original", expectedPrefix);

        httpClient.execute(nestedRequest, (nestedResponse) -> {
            log.info("XXXXX nestedResponse=[{}] [{}]", nestedResponse, nestedResponse.getHeaders()); // TODO: remove

            if (nestedResponse.getCode() != 200) {
                // TODO: Find a way to log more information on failure.
                sendError(httpResponse, 400, "Nested request had status " + nestedResponse.getCode());
                return null;
            }

            // TODO: Check if the response has expected content (a self-submitting form). If not, don't send it.

            httpResponse.setStatus(nestedResponse.getCode());
            httpResponse.setContentType(nestedResponse.getEntity().getContentType()); // TODO: handle null
            httpResponse.setContentLengthLong(nestedResponse.getEntity().getContentLength()); // TODO: handle 0
            OutputStream stream = httpResponse.getOutputStream();
            nestedResponse.getEntity().writeTo(stream);
            stream.close();
            return null;
        });
    }

    private void sendError(@Nonnull HttpServletResponse httpResponse, int status, String message) throws IOException {
        httpResponse.setStatus(status);
        httpResponse.setContentType("text/plain; charset=UTF-8");
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        OutputStream stream = httpResponse.getOutputStream();
        stream.write(message.getBytes(StandardCharsets.UTF_8));
        stream.close();
    }
}
