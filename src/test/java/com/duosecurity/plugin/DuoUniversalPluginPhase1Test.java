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

public class DuoUniversalPluginPhase1Test {
    DuoUniversalPlugin duoUniversalPlugin;

    // Just use a stub AuthenticationContext instance
    AuthenticationContext context = new AuthnContext();

    @BeforeEach
    public void setUp() {
        duoUniversalPlugin = Mockito.mock(DuoUniversalPlugin.class);
        duoUniversalPlugin.failmode = DuoUniversalPlugin.Failmode.OPEN;
        duoUniversalPlugin.username = "username";
        duoUniversalPlugin.duoClient = Mockito.mock(Client.class);

        // Mock some methods dealing with AuthenticationContext
        doNothing().when(duoUniversalPlugin).updatePluginResponse(isA(AuthenticationContext.class));
        doNothing().when(duoUniversalPlugin).storeStateInSession(isA(AuthenticationContext.class), any(String.class));
        doNothing().when(duoUniversalPlugin).issueRedirect(isA(AuthenticationContext.class), any(String.class));

        Mockito.when(duoUniversalPlugin.duoClient.generateState()).thenReturn("GOOD_STATE");

        // Call the real Phase 1 method
        Mockito.when(duoUniversalPlugin.handlePhase1(isA(AuthenticationContext.class), isA(Client.class))).thenCallRealMethod();
    }

    @Test
    public void testSuccess() throws DuoException {
        Mockito.when(duoUniversalPlugin.performHealthCheckAndFailmode(isA(Client.class), isA(DuoUniversalPlugin.Failmode.class))).thenReturn(DuoUniversalPlugin.FailmodeResult.AUTH);
        Mockito.when(duoUniversalPlugin.duoClient.createAuthUrl(anyString(), anyString())).thenReturn("url");

        ExecutionStatus result = duoUniversalPlugin.handlePhase1(context, duoUniversalPlugin.duoClient);
        assertEquals(ExecutionStatus.PAUSE, result);
    }

    @Test
    public void testFailOpen() {
        Mockito.when(duoUniversalPlugin.performHealthCheckAndFailmode(isA(Client.class), isA(DuoUniversalPlugin.Failmode.class))).thenReturn(DuoUniversalPlugin.FailmodeResult.ALLOW);

        ExecutionStatus result = duoUniversalPlugin.handlePhase1(context, duoUniversalPlugin.duoClient);
        assertEquals(ExecutionStatus.SUCCESS, result);
    }

    @Test
    public void testFailClosed() {
        Mockito.when(duoUniversalPlugin.performHealthCheckAndFailmode(isA(Client.class), isA(DuoUniversalPlugin.Failmode.class))).thenReturn(DuoUniversalPlugin.FailmodeResult.BLOCK);

        ExecutionStatus result = duoUniversalPlugin.handlePhase1(context, duoUniversalPlugin.duoClient);
        assertEquals(ExecutionStatus.FAILURE, result);
    }

    @Test
    public void testAuthUrlExceptionFailure() throws DuoException {
        Mockito.when(duoUniversalPlugin.performHealthCheckAndFailmode(isA(Client.class), isA(DuoUniversalPlugin.Failmode.class))).thenReturn(DuoUniversalPlugin.FailmodeResult.AUTH);
        Mockito.when(duoUniversalPlugin.duoClient.createAuthUrl(anyString(), anyString())).thenThrow(new DuoException("woops"));

        ExecutionStatus result = duoUniversalPlugin.handlePhase1(context, duoUniversalPlugin.duoClient);
        assertEquals(ExecutionStatus.FAILURE, result);
    }
}
