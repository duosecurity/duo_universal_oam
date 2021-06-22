package com.duosecurity.plugin;

import com.duosecurity.Client;
import com.duosecurity.exception.DuoException;
import com.duosecurity.model.HealthCheckResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DuoPluginFailmodeTest {
    DuoPlugin duoPlugin;
    Client duoClient;
    HealthCheckResponse hcResponse;

    @BeforeEach
    public void setUp() {
        duoPlugin = new DuoPlugin();
        duoClient = Mockito.mock(Client.class);
        hcResponse = Mockito.mock(HealthCheckResponse.class);
    }

    @Test
    public void testDuoHealthy() throws DuoException {
        Mockito.when(hcResponse.wasSuccess()).thenReturn(Boolean.TRUE);
        Mockito.when(duoClient.healthCheck()).thenReturn(hcResponse);

        boolean result = duoPlugin.isDuoHealthy(duoClient);

        assertEquals(true, result);
    }

    @Test
    public void testDuoUnhealthy() throws DuoException {
        Mockito.when(hcResponse.wasSuccess()).thenReturn(Boolean.FALSE);
        Mockito.when(duoClient.healthCheck()).thenReturn(hcResponse);

        boolean result = duoPlugin.isDuoHealthy(duoClient);

        assertEquals(false, result);
    }

    @Test
    public void testDuoHealthCheckException() throws DuoException {
        Mockito.when(duoClient.healthCheck()).thenThrow(new DuoException("health check exception"));

        boolean result = duoPlugin.isDuoHealthy(duoClient);

        assertEquals(false, result);
    }

    @Test
    public void testDuoHealthyFailOpen() throws DuoException {
        // If Duo is healthy, we expect to get the "auth" result since failmode is irrelevant
        Mockito.when(hcResponse.wasSuccess()).thenReturn(Boolean.TRUE);
        Mockito.when(duoClient.healthCheck()).thenReturn(hcResponse);

        DuoPlugin.FailmodeResult result = duoPlugin.performHealthCheckAndFailmode(duoClient, DuoPlugin.Failmode.OPEN);

        assertEquals(DuoPlugin.FailmodeResult.AUTH, result);
    }

    @Test
    public void testDuoUnhealthyFailOpen() throws DuoException {
        Mockito.when(hcResponse.wasSuccess()).thenReturn(Boolean.FALSE);
        Mockito.when(duoClient.healthCheck()).thenReturn(hcResponse);

        DuoPlugin.FailmodeResult result = duoPlugin.performHealthCheckAndFailmode(duoClient, DuoPlugin.Failmode.OPEN);

        assertEquals(DuoPlugin.FailmodeResult.ALLOW, result);
    }

    @Test
    public void testDuoUnhealthyFailClosed() throws DuoException {
        Mockito.when(hcResponse.wasSuccess()).thenReturn(Boolean.FALSE);
        Mockito.when(duoClient.healthCheck()).thenReturn(hcResponse);

        DuoPlugin.FailmodeResult result = duoPlugin.performHealthCheckAndFailmode(duoClient, DuoPlugin.Failmode.CLOSED);

        assertEquals(DuoPlugin.FailmodeResult.BLOCK, result);
    }

    @Test
    public void testNullFailmodeConfig() {
        Object configParam = null;

        DuoPlugin.Failmode result = DuoPlugin.determineFailmode(configParam);

        assertEquals(DuoPlugin.Failmode.CLOSED, result);
    }

    @Test
    public void testNonStringFailmodeConfig() {
        Integer configParam = 7;

        DuoPlugin.Failmode result = DuoPlugin.determineFailmode(configParam);

        assertEquals(DuoPlugin.Failmode.CLOSED, result);
    }

    @Test
    public void testNonsenseFailmodeConfig() {
        String configParam = "not a failmode";

        DuoPlugin.Failmode result = DuoPlugin.determineFailmode(configParam);

        assertEquals(DuoPlugin.Failmode.CLOSED, result);
    }

    @Test
    public void testClosedFailmodeConfig() {
        String configParam = "closed";

        DuoPlugin.Failmode result = DuoPlugin.determineFailmode(configParam);

        assertEquals(DuoPlugin.Failmode.CLOSED, result);
    }

    @Test
    public void testOpenFailmodeConfig() {
        String configParam = "open";

        DuoPlugin.Failmode result = DuoPlugin.determineFailmode(configParam);

        assertEquals(DuoPlugin.Failmode.OPEN, result);
    }

    @Test
    public void testOpenMixedCaseFailmodeConfig() {
        String configParam = "oPen";

        DuoPlugin.Failmode result = DuoPlugin.determineFailmode(configParam);

        assertEquals(DuoPlugin.Failmode.OPEN, result);
    }
}
