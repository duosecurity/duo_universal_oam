// SPDX-FileCopyrightText: 2021 Duo Security support@duosecurity.com
//
// SPDX-License-Identifier: BSD-3-Clause

package com.duosecurity.plugin;

import com.duosecurity.Client;
import com.duosecurity.exception.DuoException;
import oracle.security.am.plugin.ExecutionStatus;
import oracle.security.am.plugin.authn.AuthenticationContext;
import oracle.security.am.plugin.authn.CredentialParam;
import oracle.security.am.plugin.impl.AuthnContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doNothing;

public class DuoPluginPhase2Test {
    DuoPlugin duoPlugin;
    CredentialParam GOOD_PARAM = new CredentialParam();

    String GOOD_STATE = "GOOD_STATE";
    String BAD_STATE = "BAD_STATE";

    // Just use a stub AuthenticationContext instance
    AuthenticationContext context = new AuthnContext();

    @BeforeEach
    public void setUp() {
        duoPlugin = Mockito.mock(DuoPlugin.class);
        duoPlugin.username = "username";
        duoPlugin.duoClient = Mockito.mock(Client.class);

        doNothing().when(duoPlugin).updatePluginResponse(isA(AuthenticationContext.class));

        GOOD_PARAM.setValue("GOOD_CODE");

        // Call the real Phase 2 method
        Mockito.when(duoPlugin.handlePhase2(isA(AuthenticationContext.class), isA(Client.class), isA(CredentialParam.class))).thenCallRealMethod();
    }

    @Test
    public void testSuccess() {
        // Mock out calls dealing with AuthenticationContext functionality
        Mockito.when(duoPlugin.getStateFromRequest(isA(AuthenticationContext.class))).thenReturn(GOOD_STATE);
        Mockito.when(duoPlugin.getStateFromSession(isA(AuthenticationContext.class))).thenReturn(GOOD_STATE);

        ExecutionStatus result = duoPlugin.handlePhase2(context, duoPlugin.duoClient, GOOD_PARAM);
        assertEquals(ExecutionStatus.SUCCESS, result);
    }

    @Test
    public void testStateMismatchFailure() {
        // Mock out calls dealing with AuthenticationContext functionality
        Mockito.when(duoPlugin.getStateFromRequest(isA(AuthenticationContext.class))).thenReturn(GOOD_STATE);
        Mockito.when(duoPlugin.getStateFromSession(isA(AuthenticationContext.class))).thenReturn(BAD_STATE);

        // Call the real Phase 2 method
        Mockito.when(duoPlugin.handlePhase2(isA(AuthenticationContext.class), isA(Client.class), isA(CredentialParam.class))).thenCallRealMethod();

        // Phase 2 should return FAILURE when the states don't match
        ExecutionStatus result = duoPlugin.handlePhase2(context, duoPlugin.duoClient, GOOD_PARAM);
        assertEquals(ExecutionStatus.FAILURE, result);
    }

    @Test
    public void testApiCallExceptionFailure() throws DuoException {
        // Mock out calls dealing with AuthenticationContext functionality
        Mockito.when(duoPlugin.getStateFromRequest(isA(AuthenticationContext.class))).thenReturn(GOOD_STATE);
        Mockito.when(duoPlugin.getStateFromSession(isA(AuthenticationContext.class))).thenReturn(GOOD_STATE);

        // Mock out the Duo client call
        Mockito.when(duoPlugin.duoClient.exchangeAuthorizationCodeFor2FAResult(anyString(), anyString())).thenThrow(new DuoException("Woops"));

        // Phase 2 should return FAILURE when the Duo API call throws a DuoException
        ExecutionStatus result = duoPlugin.handlePhase2(context, duoPlugin.duoClient, GOOD_PARAM);
        assertEquals(ExecutionStatus.FAILURE, result);
    }

}
