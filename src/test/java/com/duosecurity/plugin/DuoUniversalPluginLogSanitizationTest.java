// SPDX-FileCopyrightText: 2021 Duo Security support@duosecurity.com
//
// SPDX-License-Identifier: BSD-3-Clause

package com.duosecurity.plugin;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class DuoUniversalPluginLogSanitizationTest {
    @Test
    public void testSanitizeEmailInputUnchanged() {
        String testString = "a_good_user@example.com";
        String expectedResult = testString;

        String actualResult = DuoUniversalPlugin.sanitizeForLogging(testString);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    public void testSanitizeAlphanumOnlyUnchanged() {
        String testString = "agooduser001";
        String expectedResult = testString;

        String actualResult = DuoUniversalPlugin.sanitizeForLogging(testString);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    public void testSanitizeAlphanumMixedCaseUnchanged() {
        String testString = "JamesBond007";
        String expectedResult = testString;

        String actualResult = DuoUniversalPlugin.sanitizeForLogging(testString);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    public void testSanitizeNewlinesRemoved() {
        String testString = "One\nTwo\nThree";
        String expectedResult = "OneTwoThree";

        String actualResult = DuoUniversalPlugin.sanitizeForLogging(testString);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    public void testSanitizeSpecialCharactersRemoved() {
        String testString = "One:Two\\Three:Four#Five*Six@Seven;";
        String expectedResult = "OneTwoThreeFourFiveSix@Seven";

        String actualResult = DuoUniversalPlugin.sanitizeForLogging(testString);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    public void testSanitizeNull() {
        String testString = null;
        String expectedResult = "";

        String actualResult = DuoUniversalPlugin.sanitizeForLogging(testString);

        assertEquals(expectedResult, actualResult);
    }
}