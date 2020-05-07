package org.dpppt.backend.sdk.ws.security;

import org.junit.Test;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.NumberFormat;
import java.text.ParsePosition;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class OTPKeyGeneratorTest {
    @Test
    public void testGenerateOneTimePassword() throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        int numberOfDigits = 6;
        OTPKeyGenerator otpKeyGenerator = new OTPKeyGenerator();
        String p = otpKeyGenerator.getOneTimePassword(numberOfDigits);

        assertEquals(p.length(), numberOfDigits);
        assertTrue(isNumeric(p));
    }

    private static boolean isNumeric(String str) {
        NumberFormat formatter = NumberFormat.getInstance();
        ParsePosition pos = new ParsePosition(0);
        formatter.parse(str, pos);
        return str.length() == pos.getIndex();
    }
}
