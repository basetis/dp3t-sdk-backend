package org.dpppt.backend.sdk.ws.security;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.io.IOUtils;
import org.dpppt.backend.sdk.ws.util.KeyHelper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
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
import java.time.Instant;
import java.util.Base64;

@Configuration
public class OTPKeyGenerator {
    @Value("${ws.app.otp.seedKey}")
    String seedKey;

    public String getOneTimePassword(Integer numberOfDigits) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();
        byte[] decodedKey = Base64.getDecoder().decode(loadOTPSeedKey());
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, totp.getAlgorithm());

        final Instant now = Instant.now();
        final Instant later = now.plus(totp.getTimeStep()); // TODO: Do we need a later pass?

        String otp = String.format("%0"+numberOfDigits+"d",totp.generateOneTimePassword(originalKey, now));

        return otp;
    }
    private String loadOTPSeedKey() throws IOException {
        // Start hack
        if (seedKey == null) {
            seedKey = "file:///C:/Users/ruben/.ssh/dp3t/otp_seed";
        }
        // End hack
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
