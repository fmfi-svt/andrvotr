package io.github.fmfi_svt.andrvotr;

import com.google.common.base.Strings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.annotation.Nonnull;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.security.DataSealer;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.springframework.webflow.definition.StateDefinition;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.FlowExecutionListener;
import org.springframework.webflow.execution.RequestContext;

/// Alters behavior of the "SAML2/Redirect/SSO" flow.
///
/// "SAML2/Redirect/SSO" can run either directly (requested by an end user) or as a nested request inside of
/// "andrvotr/fabricate". In the latter case, this listener will:
///
/// - On start: read the Andrvotr-Internal-Fabrication-Token request header and check its value.
/// - On success of the "DecodeMessage" state: read the Andrvotr-Internal-Fabrication-Front request header and check if
///   this {front SP, back SP} pair is an allowed connection.
/// - On every state transition: log it in the Andrvotr-Internal-Fabrication-Trace response header. This is used in
///   HttpController to check that this listener ran correctly, and returned to the client for troubleshooting purposes.
///
/// We rely on the assumption that "SAML2/Redirect/SSO" contains states named "DecodeMessage", "HandleOutboundMessage",
/// and "end". But this is technically an internal implementation detail of Shibboleth which could break in the future.
/// If needed, the flow definition is in
/// java-identity-provider/idp-conf-impl/src/main/resources/net/shibboleth/idp/flows/saml/saml2/sso-redirect-flow.xml,
/// java-identity-provider/idp-conf-impl/src/main/resources/net/shibboleth/idp/flows/saml/saml2/sso-abstract-flow.xml,
/// java-identity-provider/idp-conf-impl/src/main/resources/net/shibboleth/idp/flows/saml/saml-abstract-flow.xml.
public final class FabricationWebflowListener extends AbstractInitializableComponent implements FlowExecutionListener {

    private final @Nonnull Logger log = LoggerFactory.getLogger(FabricationWebflowListener.class);

    private Config config;

    private DataSealer dataSealer;

    public void setDataSealer(@Nonnull DataSealer sealer) {
        checkSetterPreconditions();
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
    }

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
        if (null == dataSealer) {
            throw new ComponentInitializationException("DataSealer cannot be null");
        }
    }

    @Override
    public void requestSubmitted(RequestContext context) {
        HttpServletRequest request =
                (HttpServletRequest) context.getExternalContext().getNativeRequest();

        // If the request does not have the Andrvotr-Internal-Fabrication-Token header, do nothing.
        String token = request.getHeader(Constants.HEADER_ANDRVOTR_INTERNAL_FABRICATION_TOKEN);
        if (token == null) {
            log.debug("no Andrvotr-Internal-Fabrication-Token - ignoring request");
            return;
        }

        // Check the header value to verify it is really sent by our HttpController, not a random user. (Allowing it
        // wouldn't be a huge problem, because this listener doesn't reveal any sensitive data except some coarse debug
        // info in Andrvotr-Internal-Fabrication-Trace. But just in case.)
        try {
            String content = dataSealer.unwrap(token);
            if (!Constants.ANDRVOTR_FABRICATION_TOKEN_VALUE.equals(content)) {
                throw new Exception("wrong unwrapped value");
            }
        } catch (Exception e) {
            // It would be nicer to return HTTP status 400 instead of 500, but that's hard to do from this method. This
            // error is unlikely to happen in practice. RuntimeException is good enough.
            log.warn("invalid Andrvotr-Internal-Fabrication-Token header - rejecting request", e);
            throw new RuntimeException("Andrvotr fabricate failed - invalid fabrication token");
        }

        log.info("started {} as a nested request inside andrvotr/fabricate", request.getRequestURI());
        context.getRequestScope().put(Constants.ANDRVOTR_FABRICATION_TOKEN_OK, new Object());
        addTrace(context, Constants.TRACE_START);
    }

    @Override
    public void eventSignaled(RequestContext context, Event event) {
        HttpServletRequest request =
                (HttpServletRequest) context.getExternalContext().getNativeRequest();

        // If the request does not have the Andrvotr-Internal-Fabrication-Token header, do nothing.
        if (!context.getRequestScope().contains(Constants.ANDRVOTR_FABRICATION_TOKEN_OK)) return;

        // If we're leaving the "DecodeMessage" state with the "proceed" event (not an error), check whether our
        // configuration allows connections from the front entity ID (sent by HttpController in a header) to the back
        // entity ID (found in the decoded SAML message).
        if (Constants.STATE_DECODE_MESSAGE.equals(context.getCurrentState().getId())
                && Constants.EVENT_PROCEED.equals(event.getId())) {
            addTrace(context, Constants.TRACE_ALLOWED_CONNECTION_CHECK);

            String frontID = request.getHeader(Constants.HEADER_ANDRVOTR_INTERNAL_FABRICATION_FRONT);

            // RelyingPartyContext is created by the "InitializeRelyingPartyContextFromSAMLPeer" action which runs
            // during the "DecodeMessage" state.
            ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(context);
            RelyingPartyContext rpContext = prc.getSubcontext(RelyingPartyContext.class);
            String backID = rpContext != null ? rpContext.getRelyingPartyId() : null;

            if (Strings.isNullOrEmpty(frontID)
                    || Strings.isNullOrEmpty(backID)
                    || !config.isAllowedConnection(frontID, backID)) {
                log.error("forbidden andrvotr connection: front={} back={}", frontID, backID);
                addTrace(context, Constants.TRACE_ALLOWED_CONNECTION_CHECK_FAILURE);
                throw new RuntimeException("Andrvotr fabricate failed - this connection is not allowed");
            }

            log.info("allowed andrvotr connection: front={} back={}", frontID, backID);
            addTrace(context, Constants.TRACE_ALLOWED_CONNECTION_CHECK_SUCCESS);
        }
    }

    @Override
    public void stateEntered(RequestContext context, StateDefinition previousState, StateDefinition state) {
        // If the request does not have the Andrvotr-Internal-Fabrication-Token header, do nothing.
        if (!context.getRequestScope().contains(Constants.ANDRVOTR_FABRICATION_TOKEN_OK)) return;

        // When moving from "HandleOutboundMessage" to "end", it is expected that the response is already sent, and we
        // can't add response headers anymore. Avoid the warning in addTrace.
        if (Constants.STATE_END.equals(state.getId())) return;

        // Save all entered states in a response header for troubleshooting.
        addTrace(context, state.getId());
    }

    private void addTrace(RequestContext context, String value) {
        HttpServletResponse response =
                (HttpServletResponse) context.getExternalContext().getNativeResponse();

        if (!response.isCommitted()) {
            log.debug("adding Andrvotr-Internal-Fabrication-Trace: {}", value);
            response.addHeader(Constants.HEADER_ANDRVOTR_INTERNAL_FABRICATION_TRACE, value);
        } else {
            log.warn("response already committed, cannot add trace '{}'", value);
        }
    }
}
