package io.github.fmfi_svt.andrvotr;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;

import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.session.IdPSession;
import net.shibboleth.idp.session.context.SessionContext;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.primitive.LoggerFactory;

public final class AuthorityTokenGenerator implements Function<ProfileRequestContext, List<IdPAttributeValue>> {
    @Nonnull private final Logger log = LoggerFactory.getLogger(AuthorityTokenGenerator.class);

    @Nullable public List<IdPAttributeValue> apply(@Nullable final ProfileRequestContext prc) {
        final List<IdPAttributeValue> results = new ArrayList<>();
        results.add(new StringAttributeValue("HELLO FROM ANDRVOTR!"));
        if (prc == null) {
            results.add(new StringAttributeValue("prc is null"));
        } else {
            RelyingPartyContext rpc = prc.getSubcontext(RelyingPartyContext.class);
            if (rpc == null) {
                results.add(new StringAttributeValue("no RelyingPartyContext"));
            } else {
                results.add(new StringAttributeValue("rpc.id=" + rpc.getRelyingPartyId()));
            }

            SessionContext ss = prc.getSubcontext(SessionContext.class);
            IdPSession session = ss != null ? ss.getIdPSession() : null;
            if (session != null) {
                results.add(new StringAttributeValue("sess.id=" + session.getId()));
                results.add(new StringAttributeValue("sess.princ=" + session.getPrincipalName()));
            } else {
                results.add(new StringAttributeValue("no SessionContext or IdPSession"));
            }
        }
        return results;
    }
}

