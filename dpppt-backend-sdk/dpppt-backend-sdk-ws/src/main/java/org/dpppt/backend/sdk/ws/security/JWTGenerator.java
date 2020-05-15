package org.dpppt.backend.sdk.ws.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.commons.io.IOUtils;
import org.dpppt.backend.sdk.ws.util.KeyHelper;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class JWTGenerator {
    private String privateKey;

    public  JWTGenerator(String privateKey) {
        this.privateKey = privateKey;
    }

    public String createToken(OffsetDateTime expiresAt, Integer fake) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        OffsetDateTime now = OffsetDateTime.now().withOffsetSameInstant(ZoneOffset.UTC);

        Claims claims = Jwts.claims();
        claims.put("scope", "exposed");
        claims.put("onset", String.valueOf(now.toLocalDate()));
        claims.put("fake", String.valueOf(fake));

        String key = KeyHelper.getKey(this.privateKey);
        PKCS8EncodedKeySpec keySpecX509 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key.replaceAll("\\s", "")));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(keySpecX509);

        return Jwts.builder().setClaims(claims).setId(UUID.randomUUID().toString())
                .setSubject("test-subject" + OffsetDateTime.now().withOffsetSameInstant(ZoneOffset.UTC).toString()).setExpiration(Date.from(expiresAt.toInstant()))
                .setIssuedAt(Date.from(OffsetDateTime.now().withOffsetSameInstant(ZoneOffset.UTC).toInstant())).signWith(privateKey).compact();
    }
}
