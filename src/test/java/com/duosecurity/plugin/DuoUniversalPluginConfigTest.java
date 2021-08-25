// SPDX-FileCopyrightText: 2021 Duo Security support@duosecurity.com
//
// SPDX-License-Identifier: BSD-3-Clause

package com.duosecurity.plugin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class DuoUniversalPluginConfigTest {
    DuoUniversalPlugin duoUniversalPlugin;

    @BeforeEach
    public void setUp() {
        duoUniversalPlugin = new DuoUniversalPlugin();
        duoUniversalPlugin.username = "tester";
        duoUniversalPlugin.client_id = "DIXXXXXXXXXXXXXXXXXX";
        duoUniversalPlugin.client_secret = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        duoUniversalPlugin.host = "fakehosturl";
    }

    @Test
    public void testGetDescription() {
        String ret_description = duoUniversalPlugin.getDescription();
        String description = "Duo Security's Plugin to allow users to 2FA with Duo";
        assertEquals(description, ret_description);
    }

    @Test
    public void testGetMonitoringData() {
        Map data = duoUniversalPlugin.getMonitoringData();
        assertNull(data);
    }

    @Test
    public void testGetMonitoringStatus() {
        boolean data = duoUniversalPlugin.getMonitoringStatus();
        assertFalse(data);
    }

    @Test
    public void testGetPluginName() {
        String data = duoUniversalPlugin.getPluginName();
        assertEquals(data, "DuoUniversalPlugin");
    }

    @Test
    public void testGetRevision() {
        int data = duoUniversalPlugin.getRevision();
        assertEquals(data, 0);
    }

    @Test
    public void testGetUserAgent() {
        String ua = duoUniversalPlugin.getUserAgent();
        assertNotNull(ua);
        assertTrue(ua.toLowerCase().contains("duo_universal_oam/"));
        assertTrue(ua.toLowerCase().contains("java.version"));
        assertTrue(ua.toLowerCase().contains("os.name"));
        assertTrue(ua.toLowerCase().contains("os.arch"));
        assertTrue(ua.toLowerCase().contains("os.version"));
    }
}

