package io.github.fmfi_svt.andrvotr;

import com.google.common.base.Strings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.profile.context.SpringRequestContext;
import net.shibboleth.idp.session.IdPSession;
import net.shibboleth.idp.session.context.SessionContext;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.security.DataSealer;
import net.shibboleth.shared.security.DataSealerException;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.springframework.webflow.context.ExternalContext;
import org.springframework.webflow.execution.RequestContext;

public final class AuthorityTokenGenerator extends AbstractInitializableComponent
        implements Function<ProfileRequestContext, List<IdPAttributeValue>> {

    private final @Nonnull Logger log = LoggerFactory.getLogger(AuthorityTokenGenerator.class);

    private Config config;

    private DataSealer dataSealer;

    private String idpSessionCookieName;

    private Duration tokenLifetime;

    public void setConfig(@Nonnull Config newConfig) {
        checkSetterPreconditions();
        config = Constraint.isNotNull(newConfig, "Config cannot be null");
    }

    public void setDataSealer(@Nonnull DataSealer sealer) {
        checkSetterPreconditions();
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
    }

    public void setIdpSessionCookieName(@Nonnull String name) {
        checkSetterPreconditions();
        Constraint.isFalse(Strings.isNullOrEmpty(name), "idpSessionCookieName cannot be null or empty");
        idpSessionCookieName = name;
    }

    public void setTokenLifetime(@Nonnull Duration lifetime) {
        checkSetterPreconditions();
        Constraint.isNotNull(lifetime, "Lifetime cannot be null");
        Constraint.isFalse(lifetime.isNegative() || lifetime.isZero(), "Lifetime must be positive");
        tokenLifetime = lifetime;
    }

    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (null == config) {
            throw new ComponentInitializationException("Config cannot be null");
        }
        if (null == dataSealer) {
            throw new ComponentInitializationException("DataSealer cannot be null");
        }
        if (Strings.isNullOrEmpty(idpSessionCookieName)) {
            throw new ComponentInitializationException("idpSessionCookieName cannot be null or empty");
        }
        if (null == tokenLifetime) {
            throw new ComponentInitializationException("Lifetime cannot be null");
        }
    }

    public @Nullable List<IdPAttributeValue> apply(@Nullable ProfileRequestContext prc) {
        if (prc == null) {
            // This should never happen.
            log.error("ProfileRequestContext is null. authority token not generated");
            return null;
        }

        RelyingPartyContext rpContext = prc.getSubcontext(RelyingPartyContext.class);
        String rpId = rpContext != null ? rpContext.getRelyingPartyId() : null;

        if (Strings.isNullOrEmpty(rpId)) {
            // This should never happen.
            // FYI: The hello world page also has an ID, it's "http://shibboleth.net/ns/profiles/hello".
            log.error("relying party (service provider) is unknown. authority token not generated");
            return null;
        }

        if (!config.isKnownFrontService(rpId)) {
            // If this SP has no configured connections or no API keys, don't generate the attribute.
            log.debug("'{}' is not an andrvotr front service. authority token not generated", rpId);
            return null;
        }

        if (rpId.contains("\n")) {
            log.error("unexpected newline character in entity id: {}", rpId);
            return List.of(new StringAttributeValue("E:newline_in_entity_id"));
        }

        SessionContext sessionContext = prc.getSubcontext(SessionContext.class);
        IdPSession idpSession = sessionContext != null ? sessionContext.getIdPSession() : null;
        String idpSessionId = idpSession != null ? idpSession.getId() : null;

        if (Strings.isNullOrEmpty(idpSessionId)) {
            // This can happen for example if you use the aacli.sh script.
            // It shouldn't happen for real users.
            log.error("IdP session ID is unknown. authority token not generated");
            return List.of(new StringAttributeValue("E:unknown_session_id"));
        }

        if (idpSessionId.contains("\n")) {
            log.error("unexpected newline character in IdP session ID");
            return List.of(new StringAttributeValue("E:newline_in_session_id"));
        }

        log.info("generating authority token for service={} user={}", rpId, idpSession.getPrincipalName());

        SpringRequestContext shibSpringRequestContext = prc.getSubcontext(SpringRequestContext.class);
        if (shibSpringRequestContext == null) {
            // There is no known situation where this happens.
            // (Not sure if aacli.sh has this context, but it already fails earlier.)
            log.error("SpringRequestContext is missing. authority token not generated");
            return List.of(new StringAttributeValue("E:no_spring_request_context"));
        }
        RequestContext webflowRequestContext = shibSpringRequestContext.getRequestContext();
        if (webflowRequestContext == null) {
            // There is no known situation where this happens.
            log.error("getRequestContext() is null. authority token not generated");
            return List.of(new StringAttributeValue("E:no_webflow_request_context"));
        }
        ExternalContext externalContext = webflowRequestContext.getExternalContext();
        if (externalContext == null) {
            // There is no known situation where this happens.
            log.error("getExternalContext() is null. authority token not generated");
            return List.of(new StringAttributeValue("E:no_external_context"));
        }

        String jsessionidCookieName;
        String jsessionid;
        try {
            HttpServletRequest httpRequest = (HttpServletRequest) externalContext.getNativeRequest();
            HttpServletResponse httpResponse = (HttpServletResponse) externalContext.getNativeResponse();

            // If web.xml does not explicitly configure a cookie name, getName() returns "JSESSIONID" in Jetty (tested
            // 9.4-12), but it returns null in Tomcat (tested 9-10). See https://stackoverflow.com/q/28080813.
            jsessionidCookieName =
                    httpRequest.getServletContext().getSessionCookieConfig().getName();
            if (null == jsessionidCookieName) jsessionidCookieName = "JSESSIONID";

            jsessionid = getRealJsessionid(jsessionidCookieName, httpRequest, httpResponse);
        } catch (Exception e) {
            log.error("getRealSessionid() failed. authority token not generated", e);
            return List.of(new StringAttributeValue("E:error_getting_jsessionid"));
        }

        if (Strings.isNullOrEmpty(jsessionid)) {
            // There is no known situation where this happens.
            log.error("missing JSESSIONID. authority token not generated");
            return List.of(new StringAttributeValue("E:missing_jsessionid"));
        }
        if (jsessionid.contains("\n")) {
            log.error("unexpected newline character in JSESSIONID");
            return List.of(new StringAttributeValue("E:newline_in_jsessionid"));
        }

        String cookies = (jsessionidCookieName + "=" + jsessionid) + "; " + (idpSessionCookieName + "=" + idpSessionId);

        String plainToken = Constants.AUTHORITY_TOKEN_INNER_PREFIX + "\n" + rpId + "\n" + cookies;
        log.trace("plainToken = [{}]", plainToken.replace("\n", "[\\n]"));

        try {
            String wrappedToken = dataSealer.wrap(plainToken, Instant.now().plus(tokenLifetime));
            String completeToken = Constants.AUTHORITY_TOKEN_OUTER_PREFIX + wrappedToken;
            log.trace("completeToken = [{}]", completeToken);
            return List.of(new StringAttributeValue(completeToken));
        } catch (DataSealerException e) {
            throw new RuntimeException(e);
        }
    }

    private String getRealJsessionid(String cookieName, HttpServletRequest request, HttpServletResponse response) {
        // We need the real JSESSIONID value in order to later send it in the "Cookie" header of a nested request.
        // request.getSession().getId() works as expected in Tomcat. But unfortunately not in Jetty. It does not
        // return the full JSESSIONID ("node7xxxxxx.node7"), but a truncated version ("node7xxxxxx"). To work around
        // this issue, we must read the request Cookie or response Set-Cookie header to look for the real value.

        String shortJsessionid = request.getSession().getId();
        boolean isNew = request.getSession().isNew();
        log.trace(
                "getRealJsessionid: cookieName = '{}', getSession().getId() = '{}', isNew() = {}",
                cookieName,
                shortJsessionid,
                isNew);

        if (shortJsessionid == null) {
            // This should never happen.
            throw new NullPointerException("getRealJsessionid: request.getSession().getId() is null");
        }

        String longJsessionid = null;
        if (isNew) {
            for (String setCookie : response.getHeaders("Set-Cookie")) {
                if (setCookie.startsWith(cookieName + "=")) {
                    longJsessionid = setCookie.split(";", -1)[0].split("=", 2)[1].trim();
                    log.trace("getRealJsessionid: Set-Cookie: {}", setCookie);
                }
            }
        } else if (request.isRequestedSessionIdValid()) {
            for (String cookieHeader : Collections.list(request.getHeaders("Cookie"))) {
                for (String cookie : cookieHeader.split(";", -1)) {
                    cookie = cookie.trim();
                    if (cookie.startsWith(cookieName + "=")) {
                        longJsessionid = cookie.split("=", 2)[1].trim();
                        log.trace("getRealJsessionid: Cookie: {}", cookie);
                    }
                }
            }
        } else {
            // This should not happen, because if the requested session ID is not valid, isNew should be true.
            log.trace("isNew is false and request.isRequestedSessionIdValid() is false");
        }

        if (longJsessionid == null) {
            // This could happen if the servlet container uses or accepts another session tracking mechanism instead of
            // cookies, such as SSL sessions or URL rewriting). It might also happen if the Set-Cookie header is created
            // in a weird way or at a weird time -- we expect it to be visible in response.getHeaders("Set-Cookie")
            // immediately after the getSession() call. It should not happen with Jetty or Tomcat, at least in their
            // default configuration. If it happens, fall back to getId() and hope for the best.
            log.warn(
                    "getRealJsessionid: could not find {} header named {}",
                    (isNew ? "Set-Cookie" : "Cookie"),
                    cookieName);
            return shortJsessionid;
        }

        if (longJsessionid.equals(shortJsessionid)) {
            log.trace("getRealJsessionid: found exact match");
            return longJsessionid;
        } else if (longJsessionid.contains(shortJsessionid)) {
            log.trace("getRealJsessionid: found substring match");
            return longJsessionid;
        } else {
            // This could happen if the getId() implementation returns something completely unrelated to the visible
            // JSESSIONID. It might be allowed by the servlet spec, but it hasn't been seen in practice yet.
            throw new RuntimeException(String.format(
                    "getRealJsessionid: '%s' is not a substring of '%s'", shortJsessionid, longJsessionid));
        }
    }
}
