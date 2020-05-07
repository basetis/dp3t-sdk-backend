package org.dpppt.backend.sdk.ws.security;

import com.eatthepath.otp.HmacOneTimePasswordGenerator;
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.io.IOUtils;
import org.dpppt.backend.sdk.ws.util.KeyHelper;
import org.springframework.core.io.ClassPathResource;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;


public class OTPKeyGenerator {
	
	private String seedKey = "file:///C:\\Users\\josevincente.marin\\Documents\\Projects\\Dp3t\\certificate\\seedKey";


    private final static String HOTP = "HOTP";
    private final static String TOTP = "TOTP";

    public String getOneTimePassword(String type, Integer numberOfDigits, boolean doubleLength) throws IOException, NoSuchAlgorithmException, InvalidKeyException{
        if (numberOfDigits < 6 || numberOfDigits > 8) {
            throw new IOException();
        }

        byte[] decodedKey = Base64.getDecoder().decode(loadOTPSeedKey().replaceAll("\\s", ""));

        final Instant now = Instant.now();

        int generatedOTP = 0;
        int generatedOTPx2 = 0;
        SecretKey originalKey = null;
        switch (type) {
            case TOTP:
                final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator(Duration.ofMillis(1));
                final Instant later = now.plus(totp.getTimeStep()); // TODO: Do we need a later pass?

                originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, totp.getAlgorithm());
                generatedOTP = totp.generateOneTimePassword(originalKey, now);
                if (doubleLength) {
                    generatedOTPx2 = totp.generateOneTimePassword(originalKey, now.plus(totp.getTimeStep()));
                }
                break;
            case HOTP:
                final HmacOneTimePasswordGenerator hotp = new HmacOneTimePasswordGenerator(numberOfDigits);
                originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, hotp.getAlgorithm());
                generatedOTP = hotp.generateOneTimePassword(originalKey, numberOfDigits);
                if (doubleLength) {
                    generatedOTPx2 = hotp.generateOneTimePassword(originalKey, numberOfDigits);
                }
                break;
        }

        String otp = String.format("%0"+numberOfDigits+"d", generatedOTP);
        if (doubleLength) {
            String otpx2 = String.format("%0"+numberOfDigits+"d", generatedOTPx2);
            otp = otpx2 + otp;
        }
        
        OTPManager.getInstance().setPassword(otp);

        return otp;
    }
    private String loadOTPSeedKey() throws IOException {

        if (seedKey.startsWith("keycloak:")) {
            String url = seedKey.replace("keycloak:/", "");
            return KeyHelper.getPublicKeyFromKeycloak(url);
        }

        InputStream in = null;
        if (seedKey.startsWith("classpath:/")) {
            in = new ClassPathResource(seedKey.substring("classpath:/".length())).getInputStream();
            return IOUtils.toString(in);
        } else if (seedKey.startsWith("file:///")) {
            in = new FileInputStream(seedKey.substring("file:///".length()));
            return IOUtils.toString(in);
        }
        return seedKey;
    }

    /**
     *  https://github.com/jchambers/java-otp
      * @throws NoSuchAlgorithmException
     */
    private void demoHelperKeyGenerator() throws NoSuchAlgorithmException {
        final Key key;
        final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();
        {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());

            // SHA-1 and SHA-256 prefer 64-byte (512-bit) keys; SHA512 prefers 128-byte (1024-bit) keys
            keyGenerator.init(1024);

            key = keyGenerator.generateKey();
        }
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println(encodedKey);

    }


}
