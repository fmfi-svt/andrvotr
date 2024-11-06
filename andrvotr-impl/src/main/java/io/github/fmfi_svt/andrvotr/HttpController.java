package io.github.fmfi_svt.andrvotr;

import com.google.common.base.Strings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import javax.annotation.Nonnull;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.security.DataExpiredException;
import net.shibboleth.shared.security.DataSealer;
import net.shibboleth.shared.security.DataSealerException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/andrvotr")
public final class HttpController extends AbstractInitializableComponent {

    private DataSealer dataSealer;

    public void setDataSealer(@Nonnull DataSealer sealer) {
        checkSetterPreconditions();
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
    }

    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

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
        String authorityToken = httpRequest.getParameter("andrvotr_authority_token");
        String targetUrl = httpRequest.getParameter("target_url");

        if (Strings.isNullOrEmpty(frontEntityID)
                || Strings.isNullOrEmpty(authorityToken)
                || Strings.isNullOrEmpty(targetUrl)) {
            sendError(httpResponse, 400, "Missing required parameter");
            return;
        }

        // TODO: Check API key.

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
        if (parts.length != 3
                || !Constants.AUTHORITY_TOKEN_INNER_PREFIX.equals(parts[0])
                || !frontEntityID.equals(parts[1])) {
            sendError(httpResponse, 403, "Invalid authority token");
            return;
        }

        String sessionID = parts[2];

        String expectedPrefix = "https://" + httpRequest.getServerName() + "/idp/profile/SAML2/Redirect/SSO?";
        if (!targetUrl.startsWith(expectedPrefix)) {
            sendError(httpResponse, 403, "Invalid target URL");
            return;
        }

        sendError(httpResponse, 200, "so far so good\nsessionID = " + sessionID + "\n"); // TODO
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
