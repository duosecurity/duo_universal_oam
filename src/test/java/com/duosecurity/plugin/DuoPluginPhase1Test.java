// SPDX-FileCopyrightText: 2021 Duo Security support@duosecurity.com
//
// SPDX-License-Identifier: BSD-3-Clause

package com.duosecurity.plugin;

import com.duosecurity.Client;
import com.duosecurity.exception.DuoException;
import oracle.security.am.plugin.ExecutionStatus;
import oracle.security.am.plugin.authn.AuthenticationContext;
import oracle.security.am.plugin.impl.AuthnContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doNothing;

public class DuoPluginPhase1Test {
    DuoPlugin duoPlugin;

    // Just use a stub AuthenticationContext instance
    AuthenticationContext context = new AuthnContext();

    @BeforeEach
    public void setUp() {
        duoPlugin = Mockito.mock(DuoPlugin.class);
        duoPlugin.failmode = DuoPlugin.Failmode.OPEN;
        duoPlugin.username = "username";
        duoPlugin.duoClient = Mockito.mock(Client.class);

        // Mock some methods dealing with AuthenticationContext
        doNothing().when(duoPlugin).updatePluginResponse(isA(AuthenticationContext.class));
        doNothing().when(duoPlugin).storeStateInSession(isA(AuthenticationContext.class), any(String.class));
        doNothing().when(duoPlugin).issueRedirect(isA(AuthenticationContext.class), any(String.class));

        Mockito.when(duoPlugin.duoClient.generateState()).thenReturn("GOOD_STATE");

        // Call the real Phase 1 method
        Mockito.when(duoPlugin.handlePhase1(isA(AuthenticationContext.class), isA(Client.class))).thenCallRealMethod();
    }

    @Test
    public void testSuccess() throws DuoException {
        Mockito.when(duoPlugin.performHealthCheckAndFailmode(isA(Client.class), isA(DuoPlugin.Failmode.class))).thenReturn(DuoPlugin.FailmodeResult.AUTH);
        Mockito.when(duoPlugin.duoClient.createAuthUrl(anyString(), anyString())).thenReturn("url");

        ExecutionStatus result = duoPlugin.handlePhase1(context, duoPlugin.duoClient);
        assertEquals(ExecutionStatus.PAUSE, result);
    }

    @Test
    public void testFailOpen() {
        Mockito.when(duoPlugin.performHealthCheckAndFailmode(isA(Client.class), isA(DuoPlugin.Failmode.class))).thenReturn(DuoPlugin.FailmodeResult.ALLOW);

        ExecutionStatus result = duoPlugin.handlePhase1(context, duoPlugin.duoClient);
        assertEquals(ExecutionStatus.SUCCESS, result);
    }

    @Test
    public void testFailClosed() {
        Mockito.when(duoPlugin.performHealthCheckAndFailmode(isA(Client.class), isA(DuoPlugin.Failmode.class))).thenReturn(DuoPlugin.FailmodeResult.BLOCK);

        ExecutionStatus result = duoPlugin.handlePhase1(context, duoPlugin.duoClient);
        assertEquals(ExecutionStatus.FAILURE, result);
    }

    @Test
    public void testAuthUrlExceptionFailure() throws DuoException {
        Mockito.when(duoPlugin.performHealthCheckAndFailmode(isA(Client.class), isA(DuoPlugin.Failmode.class))).thenReturn(DuoPlugin.FailmodeResult.AUTH);
        Mockito.when(duoPlugin.duoClient.createAuthUrl(anyString(), anyString())).thenThrow(new DuoException("woops"));

        ExecutionStatus result = duoPlugin.handlePhase1(context, duoPlugin.duoClient);
        assertEquals(ExecutionStatus.FAILURE, result);
    }
}
