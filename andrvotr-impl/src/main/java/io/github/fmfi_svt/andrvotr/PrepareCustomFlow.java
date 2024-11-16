package io.github.fmfi_svt.andrvotr;

import com.google.common.base.Strings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import javax.annotation.Nonnull;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.security.DataSealer;
import org.slf4j.Logger;
import org.springframework.webflow.context.ExternalContext;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

public final class PrepareCustomFlow extends AbstractInitializableComponent implements Action {

    private final @Nonnull Logger log = LoggerFactory.getLogger(PrepareCustomFlow.class);

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

    @Override
    public Event execute(RequestContext context) throws Exception {
        ExternalContext external = context.getExternalContext();
        HttpServletRequest httpRequest = (HttpServletRequest) external.getNativeRequest();
        HttpServletResponse httpResponse = (HttpServletResponse) external.getNativeResponse();

        try {
            // Check the value of Andrvotr-Internal-Token. It is usually set in HttpController on requests it makes. If
            // someone requests this URL manually, without providing that header, we reject it.
            //
            // Omitting this check wouldn't be a huge problem, because this flow is a more restricted variant of another
            // existing flow anyway. But just in case.
            String internalToken = httpRequest.getHeader("Andrvotr-Internal-Fabrication-Token");
            if (Strings.isNullOrEmpty(internalToken)) {
                throw new Exception("Token header is missing or empty");
            }
            String content = dataSealer.unwrap(internalToken);
            if (!"andrvotr-fabrication-token".equals(content)) {
                throw new Exception("Wrong unwrapped value");
            }

            return null;
        } catch (Exception e) {
            // Handle all exceptions here, because throwing an uncaught exception could cause infinite recursion. The
            // "HandleError" state, which usually handles exceptions, needs opensamlProfileRequestContext to be set. But
            // this action runs too early, before it gets set by InitializeProfileRequestContext.

            log.warn("Request did not have a valid Andrvotr-Internal-Fabrication-Token", e);

            String message = "This is an internal URL which should not be requested directly. " + e;
            httpResponse.setStatus(400);
            httpResponse.setContentType("text/plain; charset=UTF-8");
            httpResponse.setHeader("X-Content-Type-Options", "nosniff");
            OutputStream stream = httpResponse.getOutputStream();
            stream.write(message.getBytes(StandardCharsets.UTF_8));
            stream.close();

            external.recordResponseComplete();

            return new Event(this, "error");
        }
    }
}
