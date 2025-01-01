package io.github.fmfi_svt.andrvotr;

import jakarta.servlet.http.HttpServletRequest;
import java.util.function.Function;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.idp.profile.context.SpringRequestContext;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.servlet.HttpServletSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.springframework.webflow.context.ExternalContext;
import org.springframework.webflow.execution.RequestContext;

/// Works around session address binding.
///
/// Shibboleth IdP sessions remember the client IP address. If someone sends a request with a cookie value from a
/// different address, they will have to reauthenticate. (Note that by "Shibboleth IdP session" we mean interface
/// `IdPSession`, class `StorageBackedIdPSession`. and config option `idp.session.cookieName`, *not* `JSESSIONID`.)
///
/// That's a good thing, but it presents a problem for Andrvotr. The IdP session is initially created by the real user
/// and bound to their real IP address. When /.../andrvotr/fabricate sends a nested request, its remote address will be
/// localhost or similar, which is not what Shibboleth expects.
///
/// This class works around the issue by locally disabling the session address check during nested Andrvotr requests.
/// Normal requests are unaffected.
///
/// This class is registered as "shibboleth.SessionAddressLookupStrategy" by `AddressLookupStrategyInjector`. It is
/// called by "PopulateSessionContext" via authn-beans.xml and "ProcessLogout" via logout-beans.xml. Interestingly, it
/// is only called when reading existing IdP sessions, not for new ones. When StorageBackedSessionManager creates a new
/// session, it just calls HttpServletSupport.getRemoteAddr(). This might be a Shibboleth bug.
public final class AddressLookupStrategy implements Function<ProfileRequestContext, String> {
    private final @Nonnull Logger log = LoggerFactory.getLogger(AddressLookupStrategy.class);

    private final @Nullable Function<ProfileRequestContext, String> nextStrategy;

    public AddressLookupStrategy(@Nullable Function<ProfileRequestContext, String> nextStrategy) {
        log.info("initialized andrvotr AddressLookupStrategy, nextStrategy = {}", nextStrategy);
        this.nextStrategy = nextStrategy;
    }

    public @Nullable String apply(ProfileRequestContext prc) {
        // Look up the necessary objects.
        // There is no known situation where these exceptions are thrown.
        SpringRequestContext shibSpringRequestContext = prc.getSubcontext(SpringRequestContext.class);
        if (shibSpringRequestContext == null) {
            throw new RuntimeException("SpringRequestContext is missing");
        }
        RequestContext webflowRequestContext = shibSpringRequestContext.getRequestContext();
        if (webflowRequestContext == null) {
            throw new RuntimeException("getRequestContext() is null");
        }
        ExternalContext externalContext = webflowRequestContext.getExternalContext();
        if (externalContext == null) {
            throw new RuntimeException("getExternalContext() is null");
        }
        Object nativeRequest = externalContext.getNativeRequest();
        if (nativeRequest == null) {
            throw new RuntimeException("getNativeRequest() is null");
        }
        if (!(nativeRequest instanceof HttpServletRequest)) {
            throw new RuntimeException("getNativeRequest() is not a HttpServletRequest");
        }
        HttpServletRequest httpRequest = (HttpServletRequest) nativeRequest;

        // If this is a nested request sent by our HttpController to ourselves, return null.
        // When PopulateSessionContext sees that we returned null, it'll skip the checkAddress() call.
        if (webflowRequestContext.getRequestScope().contains(Constants.ANDRVOTR_FABRICATION_TOKEN_OK)) {
            log.info("forcing client address of nested request to null. original was {}", httpRequest.getRemoteAddr());
            return null;
        }

        // Return the normal address. Logic copied from
        // java-identity-provider/idp-session-impl/src/main/java/net/shibboleth/idp/session/impl/PopulateSessionContext.java.
        if (nextStrategy != null) {
            String result = nextStrategy.apply(prc);
            log.trace("client address from nextStrategy is {}", result);
            return result;
        } else {
            String result = HttpServletSupport.getRemoteAddr(httpRequest);
            log.trace("client address from httpRequest is {}", result);
            return result;
        }
    }
}
