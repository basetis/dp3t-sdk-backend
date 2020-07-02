/*
 * Copyright (c) 2020 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.dpppt.backend.sdk.ws.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.dpppt.backend.sdk.model.keycloak.KeyCloakPublicKey;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.Base64Utils;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author bachmann created on 22.04.20
 **/
public class KeyHelper {

	private static ObjectMapper objectMapper = new ObjectMapper();

	private KeyHelper() {
	}

	public static String getPublicKeyFromKeycloak(String url) throws IOException {
		URL jsonUrl = new URL(url);
		KeyCloakPublicKey publicKey = objectMapper.readValue(jsonUrl, KeyCloakPublicKey.class);
		return publicKey.getPublicKey();
	}

	public static String getKey(String key) throws IOException {
		InputStream in = null;
		if (key.startsWith("file:///")) {
			in = new FileInputStream(key.substring("file:///".length()));
			return IOUtils.toString(in);
		} else if (key.startsWith("classpath:/")) {
			in = new ClassPathResource(key.substring(11)).getInputStream();
			return IOUtils.toString(in);
		}
		return key;
	}
	
	public static PublicKey getPublickKey(String publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		String read;
		if (publicKey.startsWith("keycloak:")) {
			String url = publicKey.replace("keycloak:/", "");
			read = getPublicKeyFromKeycloak(url);
		} else {
			read = getKey(publicKey);
		}

		byte[] keyBytes = Base64.getDecoder().decode(read.replaceAll("\\s", ""));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
	
	public static PrivateKey getPrivateKey(String privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		return getPrivateKey(privateKey, "RSA");
	}

	public static PrivateKey getPrivateKey(String privateKey, String algorithm) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		String read = getKey(privateKey);
		byte[] keyBytes = Base64.getDecoder().decode(read.replaceAll("\\s", ""));
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePrivate(spec);
	}

	public static PublicKey extractPublicKey(PrivateKey key) throws InvalidKeySpecException, NoSuchAlgorithmException {
		if (key instanceof RSAPrivateCrtKey) {
			RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
			KeySpec spec = new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent());
			return KeyFactory.getInstance("RSA").generatePublic(spec);
		} else if (key instanceof ECPrivateKey) {
			ECPrivateKey ecKey = (ECPrivateKey) key;
			ECParameterSpec params = ecKey.getParameters();
			KeySpec spec = new ECPublicKeySpec(params.getG().multiply(ecKey.getD()), params);
			return KeyFactory.getInstance("EC").generatePublic(spec);
		}
		throw new UnsupportedOperationException("Key type not implemented");
	}

}
