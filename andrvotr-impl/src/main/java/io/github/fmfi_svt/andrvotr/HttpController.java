package io.github.fmfi_svt.andrvotr;

import com.google.common.base.Strings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
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
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.slf4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/andrvotr")
public final class HttpController extends AbstractInitializableComponent {

    private final @Nonnull Logger log = LoggerFactory.getLogger(HttpController.class);

    private HttpClient httpClient;

    private Config config;

    private DataSealer dataSealer;

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
        log.trace("andrvotr/fabricate [{}] [{}] [{}] [{}]", frontEntityID, apiKey, authorityToken, targetUrl);

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
        log.trace("decrypted authority token parts: {}", List.of(parts));
        if (parts.length != 3
                || !Constants.AUTHORITY_TOKEN_INNER_PREFIX.equals(parts[0])
                || !frontEntityID.equals(parts[1])) {
            sendError(httpResponse, 403, "Invalid authority token");
            return;
        }

        String cookies = parts[2];

        String expectedPrefix = "https://" + httpRequest.getServerName() + "/idp/profile/SAML2/Redirect/SSO?";
        if (!targetUrl.startsWith(expectedPrefix)) {
            sendError(httpResponse, 403, "Invalid target URL");
            return;
        }

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

        HttpGet nestedRequest = new HttpGet(targetUrl);
        nestedRequest.addHeader("Cookie", cookies);
        nestedRequest.addHeader("Andrvotr-Internal-Fabrication-Token", fabricationToken);
        nestedRequest.addHeader("Andrvotr-Internal-Fabrication-Front", frontEntityID);

        httpClient.execute(nestedRequest, (nestedResponse) -> {
            int statusCode = nestedResponse.getCode();
            String contentType = nestedResponse.getEntity().getContentType();
            long contentLength = nestedResponse.getEntity().getContentLength();

            List<String> trace = Arrays.stream(nestedResponse.getHeaders("Andrvotr-Internal-Fabrication-Trace"))
                    .map(Header::getValue)
                    .collect(Collectors.toList());

            // Only HTTP 200 (e.g. with the HTTP-POST binding) is supported for now. Adding support for 3xx responses,
            // e.g. for HTTP-Artifact SAML responses, shouldn't be too difficult but hasn't been needed yet.
            //
            // This condition relies on an internal implementation detail of saml-abstract-flow.xml: The state that
            // sends finished SAML responses has id="HandleOutboundMessage".
            boolean success = statusCode == 200
                    && contentType != null
                    && contentType.startsWith("text/html")
                    && !trace.isEmpty()
                    && "@Start".equals(trace.get(0))
                    && trace.contains("@AllowedConnectionCheckSuccess")
                    && "HandleOutboundMessage".equals(trace.get(trace.size() - 1));

            if (!success) {
                String message = String.format(
                        "Nested request failed: status=%s trace=[%s]", statusCode, String.join(",", trace));
                sendError(httpResponse, 400, message);

                // Try to log the nested response body if possible.
                try {
                    if ((contentType != null && contentType.startsWith("text/"))
                            || nestedResponse.getEntity().getContentEncoding() != null) {
                        String body = EntityUtils.toString(nestedResponse.getEntity(), 4096);
                        log.warn("andrvotr/fabricate error body: [{}]", body.replace("\n", "[\\n]"));
                    }
                } catch (Exception e) {
                }

                return null;
            }

            log.trace("nested request success trace={}", trace);
            log.info("andrvotr/fabricate success, sending SAML response to {}", frontEntityID);
            httpResponse.setStatus(statusCode);
            httpResponse.setContentType(contentType);
            if (contentLength > 0) httpResponse.setContentLengthLong(contentLength);
            OutputStream stream = httpResponse.getOutputStream();
            nestedResponse.getEntity().writeTo(stream);
            stream.close();
            return null;
        });
    }

    private void sendError(@Nonnull HttpServletResponse httpResponse, int status, String message) throws IOException {
        log.warn("andrvotr/fabricate failed with error {}: {}", status, message);
        httpResponse.setStatus(status);
        httpResponse.setContentType("text/plain; charset=UTF-8");
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        OutputStream stream = httpResponse.getOutputStream();
        stream.write(message.getBytes(StandardCharsets.UTF_8));
        stream.close();
    }
}
