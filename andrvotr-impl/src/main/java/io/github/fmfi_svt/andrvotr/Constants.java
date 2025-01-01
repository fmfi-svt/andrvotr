package io.github.fmfi_svt.andrvotr;

public final class Constants {
    private Constants() {}

    // Strings used in Andrvotr Authority Tokens. Produced by AuthorityTokenGenerator and consumed by HttpController.
    public static final String AUTHORITY_TOKEN_INNER_PREFIX = "ANDRVOTR_AUTHORITY_TOKEN_V1";
    public static final String AUTHORITY_TOKEN_OUTER_PREFIX = "A1:";

    // HTTP header names used for internal communication between HttpController and FabricationWebflowListener.
    public static final String HEADER_ANDRVOTR_INTERNAL_FABRICATION_TOKEN = "Andrvotr-Internal-Fabrication-Token";
    public static final String HEADER_ANDRVOTR_INTERNAL_FABRICATION_FRONT = "Andrvotr-Internal-Fabrication-Front";
    public static final String HEADER_ANDRVOTR_INTERNAL_FABRICATION_TRACE = "Andrvotr-Internal-Fabrication-Trace";

    // Token value used for internal communication between HttpController and FabricationWebflowListener.
    public static final String ANDRVOTR_FABRICATION_TOKEN_VALUE = "andrvotr-fabrication-token";

    // RequestContext request scope key used for internal communication between FabricationWebflowListener and
    // AddressLookupStrategy.
    public static final String ANDRVOTR_FABRICATION_TOKEN_OK = "andrvotr_fabrication_token_ok";

    // State and event names defined in the Shibboleth flow "SAML2/Redirect/SSO". Arguably an internal implementation
    // detail of Shibboleth. See class doc of FabricationWebflowListener.
    public static final String STATE_DECODE_MESSAGE = "DecodeMessage";
    public static final String STATE_HANDLE_OUTBOUND_MESSAGE = "HandleOutboundMessage";
    public static final String STATE_END = "end";
    public static final String EVENT_PROCEED = "proceed";

    // Pseudo state names written in the fabrication trace. Used for internal communication between HttpController and
    // FabricationWebflowListener, and occasionally returned to the client on errors.
    public static final String TRACE_START = "@Start";
    public static final String TRACE_ALLOWED_CONNECTION_CHECK = "@AllowedConnectionCheck";
    public static final String TRACE_ALLOWED_CONNECTION_CHECK_SUCCESS = "@AllowedConnectionCheckSuccess";
    public static final String TRACE_ALLOWED_CONNECTION_CHECK_FAILURE = "@AllowedConnectionCheckFailure";
}
