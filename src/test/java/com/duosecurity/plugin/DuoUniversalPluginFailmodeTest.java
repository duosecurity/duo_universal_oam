// SPDX-FileCopyrightText: 2021 Duo Security support@duosecurity.com
//
// SPDX-License-Identifier: BSD-3-Clause

package com.duosecurity.plugin;

import com.duosecurity.Client;
import com.duosecurity.exception.DuoException;
import com.duosecurity.model.HealthCheckResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DuoUniversalPluginFailmodeTest {
    DuoUniversalPlugin duoUniversalPlugin;
    Client duoClient;
    HealthCheckResponse hcResponse;

    @BeforeEach
    public void setUp() {
        duoUniversalPlugin = new DuoUniversalPlugin();
        duoClient = Mockito.mock(Client.class);
        hcResponse = Mockito.mock(HealthCheckResponse.class);
    }

    @Test
    public void testDuoHealthy() throws DuoException {
        Mockito.when(hcResponse.wasSuccess()).thenReturn(Boolean.TRUE);
        Mockito.when(duoClient.healthCheck()).thenReturn(hcResponse);

        boolean result = duoUniversalPlugin.isDuoHealthy(duoClient);

        assertEquals(true, result);
    }

    @Test
    public void testDuoUnhealthy() throws DuoException {
        Mockito.when(hcResponse.wasSuccess()).thenReturn(Boolean.FALSE);
        Mockito.when(duoClient.healthCheck()).thenReturn(hcResponse);

        boolean result = duoUniversalPlugin.isDuoHealthy(duoClient);

        assertEquals(false, result);
    }

    @Test
    public void testDuoHealthCheckException() throws DuoException {
        Mockito.when(duoClient.healthCheck()).thenThrow(new DuoException("health check exception"));

        boolean result = duoUniversalPlugin.isDuoHealthy(duoClient);

        assertEquals(false, result);
    }

    @Test
    public void testDuoHealthyFailOpen() throws DuoException {
        // If Duo is healthy, we expect to get the "auth" result since failmode is irrelevant
        Mockito.when(hcResponse.wasSuccess()).thenReturn(Boolean.TRUE);
        Mockito.when(duoClient.healthCheck()).thenReturn(hcResponse);

        DuoUniversalPlugin.FailmodeResult result = duoUniversalPlugin.performHealthCheckAndFailmode(duoClient, DuoUniversalPlugin.Failmode.OPEN);

        assertEquals(DuoUniversalPlugin.FailmodeResult.AUTH, result);
    }

    @Test
    public void testDuoUnhealthyFailOpen() throws DuoException {
        Mockito.when(hcResponse.wasSuccess()).thenReturn(Boolean.FALSE);
        Mockito.when(duoClient.healthCheck()).thenReturn(hcResponse);

        DuoUniversalPlugin.FailmodeResult result = duoUniversalPlugin.performHealthCheckAndFailmode(duoClient, DuoUniversalPlugin.Failmode.OPEN);

        assertEquals(DuoUniversalPlugin.FailmodeResult.ALLOW, result);
    }

    @Test
    public void testDuoUnhealthyFailClosed() throws DuoException {
        Mockito.when(hcResponse.wasSuccess()).thenReturn(Boolean.FALSE);
        Mockito.when(duoClient.healthCheck()).thenReturn(hcResponse);

        DuoUniversalPlugin.FailmodeResult result = duoUniversalPlugin.performHealthCheckAndFailmode(duoClient, DuoUniversalPlugin.Failmode.CLOSED);

        assertEquals(DuoUniversalPlugin.FailmodeResult.BLOCK, result);
    }

    @Test
    public void testNullFailmodeConfig() {
        Object configParam = null;

        DuoUniversalPlugin.Failmode result = DuoUniversalPlugin.determineFailmode(configParam);

        assertEquals(DuoUniversalPlugin.Failmode.CLOSED, result);
    }

    @Test
    public void testNonStringFailmodeConfig() {
        Integer configParam = 7;

        DuoUniversalPlugin.Failmode result = DuoUniversalPlugin.determineFailmode(configParam);

        assertEquals(DuoUniversalPlugin.Failmode.CLOSED, result);
    }

    @Test
    public void testNonsenseFailmodeConfig() {
        String configParam = "not a failmode";

        DuoUniversalPlugin.Failmode result = DuoUniversalPlugin.determineFailmode(configParam);

        assertEquals(DuoUniversalPlugin.Failmode.CLOSED, result);
    }

    @Test
    public void testClosedFailmodeConfig() {
        String configParam = "closed";

        DuoUniversalPlugin.Failmode result = DuoUniversalPlugin.determineFailmode(configParam);

        assertEquals(DuoUniversalPlugin.Failmode.CLOSED, result);
    }

    @Test
    public void testOpenFailmodeConfig() {
        String configParam = "open";

        DuoUniversalPlugin.Failmode result = DuoUniversalPlugin.determineFailmode(configParam);

        assertEquals(DuoUniversalPlugin.Failmode.OPEN, result);
    }

    @Test
    public void testOpenMixedCaseFailmodeConfig() {
        String configParam = "oPen";

        DuoUniversalPlugin.Failmode result = DuoUniversalPlugin.determineFailmode(configParam);

        assertEquals(DuoUniversalPlugin.Failmode.OPEN, result);
    }
}
