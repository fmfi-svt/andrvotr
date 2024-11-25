package io.github.fmfi_svt.andrvotr;

import com.google.common.base.Strings;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.utilities.java.support.collection.Pair;
import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;

public final class Config extends AbstractInitializableComponent {

    private @Nullable String apiKeysString;

    private @Nonnull Set<Pair<String, String>> apiKeys = Collections.emptySet();

    private @Nonnull Set<String> apiKeyFronts = Collections.emptySet();

    private @Nullable String allowedConnectionsString;

    private @Nonnull Set<Pair<String, String>> allowedConnections = Collections.emptySet();

    private @Nonnull Set<String> allowedConnectionFronts = Collections.emptySet();

    public void setApiKeys(@Nullable String string) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        apiKeysString = string;
    }

    public void setAllowedConnections(@Nullable String string) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        allowedConnectionsString = string;
    }

    private static void parsePairs(
            String input,
            String separator,
            String displayName,
            String firstName,
            String secondName,
            Set<Pair<String, String>> outputPairs,
            Set<String> outputFirsts)
            throws ComponentInitializationException {
        if (Strings.isNullOrEmpty(input)) return;

        if (!(input.startsWith("[") && input.endsWith("]"))) {
            throw new ComponentInitializationException(String.format(
                    "Could not parse %s value: It should start with '[' and end with ']'. Maybe a \\ is missing at the end of some line.",
                    displayName));
        }

        // -1 because of https://errorprone.info/bugpattern/StringSplitter
        for (String part : input.substring(1, input.length() - 1).split("\\s+", -1)) {
            if (Strings.isNullOrEmpty(part)) continue;

            String[] subparts = part.split(separator, -1);
            if (subparts.length != 2) {
                throw new ComponentInitializationException(String.format(
                        "Could not parse %s value: Expected a token containing one '%s', but found '%s'",
                        displayName, separator, part));
            }
            if (Strings.isNullOrEmpty(subparts[0])) {
                throw new ComponentInitializationException(String.format(
                        "Could not parse %s value: The %s is empty in '%s'", displayName, firstName, part));
            }
            if (Strings.isNullOrEmpty(subparts[1])) {
                throw new ComponentInitializationException(String.format(
                        "Could not parse %s value: The %s is empty in '%s'", displayName, secondName, part));
            }
            outputPairs.add(new Pair<>(subparts[0], subparts[1]));
            outputFirsts.add(subparts[0]);
        }
    }

    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        apiKeys = new HashSet<>();
        apiKeyFronts = new HashSet<>();
        parsePairs(apiKeysString, "##", "andrvotr.apiKeys", "front entity ID", "API key", apiKeys, apiKeyFronts);

        allowedConnections = new HashSet<>();
        allowedConnectionFronts = new HashSet<>();
        parsePairs(
                allowedConnectionsString,
                ">>",
                "andrvotr.allowedConnections",
                "front entity ID",
                "back entity ID",
                allowedConnections,
                allowedConnectionFronts);
    }

    public boolean isKnownFrontService(String frontID) {
        return apiKeyFronts.contains(frontID) && allowedConnectionFronts.contains(frontID);
    }

    public boolean isValidApiKey(String frontID, String apiKey) {
        return apiKeys.contains(new Pair<>(frontID, apiKey));
    }

    public boolean isAllowedConnection(String frontID, String backID) {
        return allowedConnections.contains(new Pair<>(frontID, backID));
    }
}
