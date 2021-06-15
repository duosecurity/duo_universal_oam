package com.duosecurity.plugin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class DuoPluginConfigTest {
    DuoPlugin duoPlugin;

    @BeforeEach
    public void setUp() {
        duoPlugin = new DuoPlugin();
        duoPlugin.username = "tester";
        duoPlugin.ikey = "DIXXXXXXXXXXXXXXXXXX";
        duoPlugin.skey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        duoPlugin.host = "fakehosturl";
        // duoPlugin.failmode = "secure";
    }

    /**
    @Test
    public void testPerformPreauth_whenFailmodeSecure() {
        duoPlugin.failmode = "secure";
        try {
            assertEquals("auth", duoPlugin.performPreAuth());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    } **/

    /**
    @Test
    public void testPerformPreauth_whenFailmodeSafeAndDuoUnreachable() {
        duoPlugin.failmode = "safe";
        try {
            assertEquals("allow", duoPlugin.performPreAuth());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    } **/

    /**
    @Test
    public void testPerformPreauth_whenFailmodeInvalid() {
        duoPlugin.failmode = "invalidfailmode";
        try {
            duoPlugin.performPreAuth();
            fail("Expected IllegalArgumentException thrown.");
        } catch (IllegalArgumentException e) {

        } catch (Exception e) {
            fail("Expected IllegalArgumentException thrown.");
        }
    } **/

    @Test
    public void testGetDescription() {
        String ret_description = duoPlugin.getDescription();
        String description = "Duo Security's Plugin to allow users to 2FA with Duo";
        assertEquals(description, ret_description);
    }

    @Test
    public void testGetMonitoringData() {
        Map data = duoPlugin.getMonitoringData();
        assertNull(data);
    }

    @Test
    public void testGetMonitoringStatus() {
        boolean data = duoPlugin.getMonitoringStatus();
        assertFalse(data);
    }

    @Test
    public void testGetPluginName() {
        String data = duoPlugin.getPluginName();
        assertEquals(data, "DuoPlugin");
    }

    @Test
    public void testGetRevision() {
        int data = duoPlugin.getRevision();
        assertEquals(data, 0);
    }

    @Test
    public void testGetUserAgent() {
        String ua = duoPlugin.getUserAgent();
        assertNotNull(ua);
        assertTrue(ua.toLowerCase().contains("duo_universal_oam/"));
        assertTrue(ua.toLowerCase().contains("java.version"));
        assertTrue(ua.toLowerCase().contains("os.name"));
        assertTrue(ua.toLowerCase().contains("os.arch"));
        assertTrue(ua.toLowerCase().contains("os.version"));
    }
}

