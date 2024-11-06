package io.github.fmfi_svt.andrvotr;

import com.google.common.base.Strings;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.Function;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
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

public final class AuthorityTokenGenerator extends AbstractInitializableComponent
        implements Function<ProfileRequestContext, List<IdPAttributeValue>> {

    private final @Nonnull Logger log = LoggerFactory.getLogger(AuthorityTokenGenerator.class);

    private DataSealer dataSealer;

    private Duration tokenLifetime;

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

        if (null == dataSealer) {
            throw new ComponentInitializationException("DataSealer cannot be null");
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

        // TODO: If this SP has no configured backends or no API keys, return null without logging.

        if (rpId.contains("\n")) {
            log.error("unexpected newline character in entity id: {}", rpId);
            return List.of(new StringAttributeValue("E:newline_in_entity_id"));
        }

        SessionContext sessionContext = prc.getSubcontext(SessionContext.class);
        IdPSession session = sessionContext != null ? sessionContext.getIdPSession() : null;
        String sessionId = session != null ? session.getId() : null;

        if (Strings.isNullOrEmpty(sessionId)) {
            // This can happen for example if you use the aacli.sh script.
            // It shouldn't happen for real users.
            log.error("user session id is unknown. authority token not generated");
            return List.of(new StringAttributeValue("E:unknown_session_id"));
        }

        if (sessionId.contains("\n")) {
            log.error("unexpected newline character in session id");
            return List.of(new StringAttributeValue("E:newline_in_session_id"));
        }

        log.info("generating authority token for service={} user={}", rpId, session.getPrincipalName());
        String plainToken = Constants.AUTHORITY_TOKEN_INNER_PREFIX + "\n" + rpId + "\n" + sessionId;
        try {
            String wrappedToken = dataSealer.wrap(plainToken, Instant.now().plus(tokenLifetime));
            String completeToken = Constants.AUTHORITY_TOKEN_OUTER_PREFIX + wrappedToken;
            return List.of(new StringAttributeValue(completeToken));
        } catch (DataSealerException e) {
            throw new RuntimeException(e);
        }
    }
}
