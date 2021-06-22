package com.duosecurity.plugin;

import java.util.Map;
import java.util.logging.Level;
import javax.security.auth.Subject;

import com.duosecurity.exception.DuoException;
import com.duosecurity.model.HealthCheckResponse;
import oracle.security.am.plugin.ExecutionStatus;
import oracle.security.am.plugin.MonitoringData;
import oracle.security.am.plugin.PluginAttributeContextType;
import oracle.security.am.plugin.PluginConfig;
import oracle.security.am.plugin.PluginResponse;
import oracle.security.am.plugin.authn.AbstractAuthenticationPlugIn;
import oracle.security.am.plugin.authn.AuthenticationContext;
import oracle.security.am.plugin.authn.AuthenticationException;
import oracle.security.am.plugin.authn.CredentialParam;
import oracle.security.am.plugin.authn.PluginConstants;
import oracle.security.am.plugin.impl.CredentialMetaData;
import oracle.security.am.plugin.impl.UserAction;
import oracle.security.am.plugin.impl.UserActionContext;
import oracle.security.am.plugin.impl.UserActionMetaData;
import oracle.security.am.plugin.impl.UserContextData;
import oracle.security.am.engines.common.identity.provider.UserIdentityProvider;
import oracle.security.am.engines.common.identity.provider.UserInfo;
import oracle.security.am.engines.common.identity.provider.exceptions.IdentityProviderException;
import oracle.security.am.common.utilities.principal.OAMGUIDPrincipal;
import oracle.security.am.common.utilities.principal.OAMUserDNPrincipal;
import oracle.security.am.common.utilities.principal.OAMUserPrincipal;
import oracle.security.am.engines.common.identity.provider.UserIdentityProviderFactory;

import com.duosecurity.Client;
import com.duosecurity.model.Token;

public class DuoPlugin extends AbstractAuthenticationPlugIn {

    private static final String JAR_VERSION = "0.1.0";
    private static final String IKEY_PARAM = "ikey";
    private static final String SKEY_PARAM = "skey";
    private static final String HOST_PARAM = "host";
    private static final String REDIRECT_PARAM = "Redirect URL";
    private static final String STORE_PARAM = "User Store";
    private static final String FAILMODE = "Fail mode";
    private static final String SESSION_STATE = "duoState";
    private static final String CREDENTIAL_NAME_CODE = "duo_code";
    private static final String CREDENTIAL_NAME_STATE = "state";

    // Regex-syntax string, indicating the things to remove during sanitization of a string
    private static final String SANITIZING_PATTERN = "[^A-Za-z0-9_@.]";

    // Initialization parameters
    String ikey = null;
    String skey = null;
    String host = null;
    String redirectUrl = null;
    Failmode failmode = Failmode.CLOSED;
    String userStore = null;

    Client duoClient;
    String username = null;

    @Override
    public ExecutionStatus initialize(final PluginConfig config) throws IllegalArgumentException {

        super.initialize(config);

        LOGGER.log(Level.INFO, this.getClass().getName() + " initializing Duo Plugin " + JAR_VERSION);
        try {
            this.ikey = (String) config.getParameter(IKEY_PARAM);
            this.skey = (String) config.getParameter(SKEY_PARAM);
            this.host = (String) config.getParameter(HOST_PARAM);
            this.redirectUrl = (String) config.getParameter(REDIRECT_PARAM);
            this.failmode = this.determineFailmode(config.getParameter(FAILMODE));
            String configuredStore = (String) config.getParameter(STORE_PARAM);
            if (configuredStore != null && !configuredStore.equals("")) {
                LOGGER.log(Level.CONFIG, "Using custom User Store " + configuredStore);
                this.userStore = configuredStore;
            } else {
                LOGGER.log(Level.CONFIG, "Using default User Store");
            }
            // TODO any validation on redirect URL?

            this.duoClient = new Client(this.ikey, this.skey, this.host, this.redirectUrl);
            this.duoClient.appendUserAgentInfo(getUserAgent());
        } catch (Exception error) {
            LOGGER.log(Level.SEVERE,
                       "Error initializing Duo plugin",
                       error);
            throw new IllegalArgumentException("Could not initialize Duo Plugin with provided parameters");
        }

        LOGGER.log(Level.CONFIG, "Fail mode is set to fail " + (this.failmode == Failmode.CLOSED ? "closed" : "open"));

        return ExecutionStatus.SUCCESS;
    }

    static Failmode determineFailmode(Object configParam) {
        // Determine failmode from the provided config value.  Default to CLOSED unless we can for sure determine OPEN
        if (configParam == null) {
            LOGGER.log(Level.CONFIG, "Failmode parameter was unexpectedly missing");
            return Failmode.CLOSED;
        }

        if (!(configParam instanceof String)) {
            LOGGER.log(Level.CONFIG, "Failmode parameter was unexpectedly not a string");
            return Failmode.CLOSED;
        }

        String configString = (String)configParam;
        if ("open".equalsIgnoreCase(configString)) {
            return Failmode.OPEN;
        } else {
            return Failmode.CLOSED;
        }
    }

    @Override
    public ExecutionStatus process(final AuthenticationContext context) throws AuthenticationException {

        LOGGER.log(Level.INFO, "Duo plugin starting");
        ExecutionStatus status = ExecutionStatus.FAILURE;
        this.username = getUserName(context);

        // attempts to get the Duo code value that is sent back to the plugin URL after finishing with the prompt
        CredentialParam param = context.getCredential().getParam(CREDENTIAL_NAME_CODE);

        if ((param == null) || (param.getValue() == null) || (param.getValue().toString().length() == 0)) {
            LOGGER.log(Level.INFO, "Duo phase 1 starting");

            // We didn't have a Duo code, this is probably the first time through the plugin
            status = this.handlePhase1(context, this.duoClient);
        } else {
            LOGGER.log(Level.INFO, "Duo phase 2 starting");

            // We got a Duo code, so we need to validate it
            status = this.handlePhase2(context, this.duoClient, param);
        }

        return status;
    }

    /**
     * Run the first phase of the Duo plugin logic:
     * - Do a health check and invoke failmode if necessary
     * - If Duo is healthy, issue the redirect
     * 
     * @param context The OAM authn context
     * @param duoClient The Duo SDK client
     * @return The plugin status after running phase 1
     */
    ExecutionStatus handlePhase1(final AuthenticationContext context, final Client duoClient) {
        // TODO health check and failmode considerations will go here later

        // Generate state and store it in the OAM session
        String duoState = duoClient.generateState();
        this.storeStateInSession(context, duoState);

        // Generate the auth URL to send the user to
        String authUrl;
        try {
            authUrl = duoClient.createAuthUrl(this.username, duoState);
        } catch (DuoException error) {
            LOGGER.log(Level.SEVERE,
                    "An exception occurred while "
                            + sanitizeForLogging(this.username)
                            + " attempted Duo two-factor authentication.",
                    error);
            this.updatePluginResponse(context);
            return ExecutionStatus.FAILURE;
        }
        LOGGER.log(Level.FINE, "Generated auth url " + authUrl);

        // Tell OAM to redirect the user
        this.issueRedirect(context, authUrl);

        LOGGER.log(Level.INFO, "Duo phase 1 complete, redirecting");
        this.updatePluginResponse(context);
        return ExecutionStatus.PAUSE;
    }

    FailmodeResult performHealthCheckAndFailmode(final Client duoClient, Failmode failmode) {
        boolean isDuoHealthy = this.isDuoHealthy(duoClient);
        if (isDuoHealthy) {
            return FailmodeResult.AUTH;
        }

        if (Failmode.OPEN == failmode) {
            return FailmodeResult.ALLOW;
        } else {
            return FailmodeResult.BLOCK;
        }
    }

    boolean isDuoHealthy(final Client duoClient) {
        try {
            HealthCheckResponse checkResponse = duoClient.healthCheck();
            if (checkResponse == null || !checkResponse.wasSuccess()) {
                LOGGER.log(Level.FINE, "Duo health check reports Duo is unavailable");
                return false;
            }
        } catch (DuoException de) {
            LOGGER.log(Level.WARNING, "Duo health check failed with error", de);
            return false;
        }
        return true;
    }

    void storeStateInSession(AuthenticationContext context, String duoState) {
        PluginResponse duoStateSession = new PluginResponse(SESSION_STATE, duoState, PluginAttributeContextType.SESSION);
        context.addResponse(duoStateSession);
    }

    /**
     * Set up a redirect to the Duo authentication URL
     *
     * @param context the OAM context
     * @param authUrl the URL to redirect the user to
     */
    void issueRedirect(AuthenticationContext context, String authUrl) {
        UserContextData codeResponseContext = new UserContextData(CREDENTIAL_NAME_CODE, CREDENTIAL_NAME_CODE, new CredentialMetaData((PluginConstants.PASSWORD)));
        UserContextData stateResponseContext = new UserContextData(CREDENTIAL_NAME_STATE, CREDENTIAL_NAME_STATE, new CredentialMetaData((PluginConstants.PASSWORD)));
        UserContextData urlContext = new UserContextData(authUrl, new CredentialMetaData("URL"));
        UserActionContext actionContext = new UserActionContext();
        actionContext.getContextData().add(codeResponseContext);
        actionContext.getContextData().add(stateResponseContext);
        actionContext.getContextData().add(urlContext);

        UserActionMetaData userAction = UserActionMetaData.REDIRECT_GET;
        UserAction action = new UserAction(actionContext, userAction);
        context.setAction(action);
    }

    /**
     * Run the second phase of the Duo plugin
     * - Exchange the access code for an Authn Token
     * - Validate the Token
     * 
     * @param context The OAM authn context
     * @param duoClient The Duo SDK Client
     * @param codeParam The Duo access code, guaranteed not null or empty
     * @return The plugin status after running phase 2
     */
    ExecutionStatus handlePhase2(final AuthenticationContext context, final Client duoClient, CredentialParam codeParam) throws AuthenticationException{

        // Get the expected parameters
        String duoCode = codeParam.getValue().toString();
        LOGGER.log(Level.FINE, "Got Duo code " + duoCode.substring(0, 4));

        // Get the state sent by Duo
        String duoState = this.getStateFromRequest(context);

        // Get the original state from the session
        String contextState = this.getStateFromSession(context);

        if (!duoState.equals(contextState)) {
            LOGGER.log(Level.SEVERE, "State validation was unsuccessful");
            this.updatePluginResponse(context);
            return ExecutionStatus.FAILURE;
        }

        // Exchange the code for the auth token from Duo
        try {
          Token duoToken = duoClient.exchangeAuthorizationCodeFor2FAResult(duoCode, this.username);
          LOGGER.log(Level.FINE, "Got and validated Duo token successfully");
          // TODO This will raise if the username doesn't match but is there anything we want to check?
        } catch (DuoException error) {
            LOGGER.log(Level.SEVERE,
                       "An exception occurred while "
                       + sanitizeForLogging(this.username)
                       + " attempted Duo two-factor authentication.",
                       error);
            this.updatePluginResponse(context);
            return ExecutionStatus.FAILURE;
        }

        this.updatePluginResponse(context);
        
        return ExecutionStatus.SUCCESS;
    }

    /**
     * Pull the State parameter, which should have been returned by Duo, out of the request
     *
     * @param context the OAM context
     * @return The value of the state parameter sent by Duo
     * @throws AuthenticationException if the state parameter was missing
     */
    String getStateFromRequest(AuthenticationContext context) throws AuthenticationException {
        CredentialParam stateParam = context.getCredential().getParam(CREDENTIAL_NAME_STATE);
        if (stateParam == null || stateParam.getValue() == null) {
            LOGGER.log(Level.SEVERE, "State parameter was not returned from Duo");
            throw new AuthenticationException("Duo State parameter missing");
        }
        return stateParam.getValue().toString();
    }

    /**
     * Pull the State parameter out of the session, where it should have been stored
     *
     * @param context the OAM context
     * @return The value of the state parameter stored in the session
     * @throws AuthenticationException if the state parameter was missing
     */
    String getStateFromSession(AuthenticationContext context) throws AuthenticationException {
        PluginResponse sessionState = context.getResponse(PluginAttributeContextType.SESSION, SESSION_STATE);
        if (sessionState == null || sessionState.getValue() == null) {
            LOGGER.log(Level.SEVERE, "State parameter was not available from the session");
            throw new AuthenticationException("Session State parameter missing");
        }
        return sessionState.getValue().toString();
    }


    @Override
    public String getDescription() {
        return "Duo Security's Plugin to allow users to 2FA with Duo";
    }

    @Override
    public Map<String, MonitoringData> getMonitoringData() {
        // Plugins can log DMS data which will be picked by the Auth framework
        // and logged.
        return null;
    }

    @Override
    public boolean getMonitoringStatus() {
        // Indicates if logging DMS data is enabled for the plugins.
        return false;
    }

    @Override
    public void setMonitoringStatus(final boolean status) {

    }

    @Override
    public String getPluginName() {
        return "DuoPlugin";
    }


    @Override
    public int getRevision() {
        return 0;
    }

    void updatePluginResponse(final AuthenticationContext context) {
        // TODO figure out what in here is unnecessary
        String retAttrs[] = (String[]) null;

        String userName = getUserName(context);
        UserIdentityProvider provider = null;
        UserInfo user = null;
        try {
            provider = getUserIdentityProvider();
            user = provider.locateUser(userName);
            retAttrs = provider.getReturnAttributes();

        } catch (Exception error) {
            LOGGER.log(Level.SEVERE,
                       "OAM error retrieving user profile from configured "
                       + "identity store during Duo two-factor", error);

        }

        String userIdentity = user.getUserId();
        String userDN = user.getDN();
        Subject subject = new Subject();
        subject.getPrincipals().add(new OAMUserPrincipal(userIdentity));
        subject.getPrincipals().add(new OAMUserDNPrincipal(userDN));

        if (user.getGUID() != null) {
            subject.getPrincipals().add(new OAMGUIDPrincipal(user.getGUID()));
        } else {
            subject.getPrincipals().add(new OAMGUIDPrincipal(userIdentity));
        }
        context.setSubject(subject);

        CredentialParam param = new CredentialParam();
        param.setName(PluginConstants.KEY_USERNAME_DN);
        param.setType("string");
        param.setValue(userDN);
        context.getCredential().addCredentialParam(PluginConstants.KEY_USERNAME_DN, param);

        PluginResponse rsp = new PluginResponse();
        rsp = new PluginResponse();
        rsp.setName(PluginConstants.KEY_AUTHENTICATED_USER_NAME);
        rsp.setType(PluginAttributeContextType.LITERAL);
        rsp.setValue(userIdentity);
        context.addResponse(rsp);

        rsp = new PluginResponse();
        rsp.setName(PluginConstants.KEY_RETURN_ATTRIBUTE);
        rsp.setType(PluginAttributeContextType.LITERAL);
        rsp.setValue(retAttrs);
        context.addResponse(rsp);

        rsp = new PluginResponse();
        rsp.setName("authn_policy_id");
        rsp.setType(PluginAttributeContextType.REQUEST);
        rsp.setValue(context.getAuthnScheme().getName());
        context.addResponse(rsp);

    }

    private String getUserName(final AuthenticationContext context) {
        String userName = null;

        CredentialParam param = context.getCredential().getParam("KEY_USERNAME");

        if (param != null) {
            userName = (String) param.getValue();
        }

        if ((userName == null) || (userName.length() == 0)) {
            userName = context.getStringAttribute("KEY_USERNAME");
        }

        return userName;
    }

    private UserIdentityProvider getUserIdentityProvider() throws IdentityProviderException {
        if (this.userStore == null) {
            return UserIdentityProviderFactory.getProvider();
        } else {
            return UserIdentityProviderFactory.getProvider(this.userStore);
        }
    }

    static String getUserAgent() {
        String userAgent = "duo_universal_oam/jar " + JAR_VERSION  + " (";

        userAgent = addKeyValueToUserAgent(userAgent, "java.version") + "; ";
        userAgent = addKeyValueToUserAgent(userAgent, "os.name") + "; ";
        userAgent = addKeyValueToUserAgent(userAgent, "os.arch") + "; ";
        userAgent = addKeyValueToUserAgent(userAgent, "os.version");

        userAgent += ")";

        return userAgent;
    }

    private static String addKeyValueToUserAgent(String userAgent, String key) {
        return userAgent + (key + "=" + System.getProperty(key));
    }

    static String sanitizeForLogging(String stringToSanitize) {
      if (stringToSanitize == null) {
        return "";
      }

      return stringToSanitize.replaceAll(SANITIZING_PATTERN, "");        
    }

    public enum Failmode {
        OPEN,
        CLOSED,
    }

    public enum FailmodeResult {
        ALLOW,
        AUTH,
        BLOCK,
    }
}
