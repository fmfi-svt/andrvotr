package io.github.fmfi_svt.andrvotr;

import com.google.common.base.Strings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import javax.annotation.Nonnull;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.context.SpringRequestContext;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.messaging.context.SAMLMessageReceivedEndpointContext;
import org.slf4j.Logger;

public final class PostprocessDecodedMessage extends AbstractProfileAction {

    private final @Nonnull Logger log = LoggerFactory.getLogger(PostprocessDecodedMessage.class);

    private Config config;

    public void setConfig(@Nonnull Config newConfig) {
        checkSetterPreconditions();
        config = Constraint.isNotNull(newConfig, "Config cannot be null");
    }

    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (null == config) {
            throw new ComponentInitializationException("Config cannot be null");
        }
    }

    @Override
    protected void doExecute(@Nonnull ProfileRequestContext prc) {
        HttpServletRequest servletRequest = (HttpServletRequest) prc.getSubcontext(SpringRequestContext.class)
                .getRequestContext()
                .getExternalContext()
                .getNativeRequest();
        String originalURL = servletRequest.getHeader("Andrvotr-Internal-Fabrication-Original");
        if (Strings.isNullOrEmpty(originalURL)) {
            throw new RuntimeException("Andrvotr-Internal-Fabrication-Original is null or empty");
        }

        String frontId = servletRequest.getHeader("Andrvotr-Internal-Fabrication-Front");
        if (Strings.isNullOrEmpty(frontId)) {
            throw new RuntimeException("Andrvotr-Internal-Fabrication-Front is null or empty");
        }

        RelyingPartyContext rpContext = prc.getSubcontext(RelyingPartyContext.class);
        String backId = rpContext != null ? rpContext.getRelyingPartyId() : null;
        if (Strings.isNullOrEmpty(backId)) {
            throw new RuntimeException("RelyingPartyContext.getRelyingPartyId() is null or empty");
        }

        if (!config.isAllowedConnection(frontId, backId)) {
            throw new RuntimeException(String.format("Connection from %s to %s is not allowed", frontId, backId));
        }

        // The current request URL is our custom flow, but the Destination="" attribute of the AuthnRequest still points
        // to the original flow. When they don't match, the request is rejected by ReceivedEndpointSecurityHandler. We
        // must tell it to check for the original URL.
        //
        // It's needlessly complicated because SAMLMessageReceivedEndpointContext.setRequestURL() is not public. :(
        //
        // The following hack relies on the assumption that the SAMLMessageReceivedEndpointContext(HttpServletRequest)
        // constructor only calls request.getRequestURL() and does not use the request in any other way. So we build a
        // fake request that overrides that specific method to return the required value.
        HttpServletRequest fakeRequest = new HttpServletRequestWrapper(servletRequest) {
            @Override
            public StringBuffer getRequestURL() {
                return new StringBuffer(originalURL);
            }
        };
        prc.getInboundMessageContext().addSubcontext(new SAMLMessageReceivedEndpointContext(fakeRequest));
    }
}
