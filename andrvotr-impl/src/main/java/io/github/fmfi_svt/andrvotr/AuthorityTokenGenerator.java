package io.github.fmfi_svt.andrvotr;

import com.google.common.base.Strings;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.time.Instant;
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

    private Duration tokenLifetime;

    public void setConfig(@Nonnull Config newConfig) {
        checkSetterPreconditions();
        config = Constraint.isNotNull(newConfig, "Config cannot be null");
    }

    public void setDataSealer(@Nonnull DataSealer sealer) {
        checkSetterPreconditions();
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
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
        if (null == tokenLifetime) {
            throw new ComponentInitializationException("Lifetime cannot be null");
        }
    }

    @Override
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
        Object nativeRequest = externalContext.getNativeRequest();
        if (nativeRequest == null) {
            // There is no known situation where this happens.
            log.error("getNativeRequest() is null. authority token not generated");
            return List.of(new StringAttributeValue("E:no_native_request"));
        }
        String jsessionid;
        if (nativeRequest instanceof HttpServletRequest httpRequest) {
            jsessionid = httpRequest.getSession().getId();
        } else {
            // There is no known situation where this happens.
            log.error("nativeRequest is not HttpServletRequest but {}. authority token not generated", nativeRequest);
            return List.of(new StringAttributeValue("E:wrong_native_request_type"));
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
        // TODO: Maybe also check for other characters which are forbidden in cookie values.

        log.info("generating authority token for service={} user={}", rpId, idpSession.getPrincipalName());

        String plainToken =
                Constants.AUTHORITY_TOKEN_INNER_PREFIX + "\n" + rpId + "\n" + jsessionid + "\n" + idpSessionId;
        try {
            String wrappedToken = dataSealer.wrap(plainToken, Instant.now().plus(tokenLifetime));
            String completeToken = Constants.AUTHORITY_TOKEN_OUTER_PREFIX + wrappedToken;
            return List.of(new StringAttributeValue(completeToken));
        } catch (DataSealerException e) {
            throw new RuntimeException(e);
        }
    }
}
