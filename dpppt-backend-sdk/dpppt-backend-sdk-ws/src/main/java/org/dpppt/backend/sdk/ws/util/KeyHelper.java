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
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.apache.commons.io.IOUtils;
import org.dpppt.backend.sdk.model.keycloak.KeyCloakPublicKey;

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
		}
		return key;
	}
	
	public static PublicKey getPublickKey(String publicKey) throws Exception{
		
		byte[] readBytes = null;
		
		if(publicKey.startsWith("file:///")) {
			readBytes = Files.readAllBytes(Paths.get(publicKey.substring("file:///".length())));
		}else {
			readBytes = publicKey.getBytes();	
		}
		
		byte[] keyBytes = Base64.getDecoder().decode(readBytes);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");	    
		return kf.generatePublic(spec);
	}
	
	public static PrivateKey getPrivateKey(String privateKey) throws Exception{
		
		byte[] readBytes = null;
		
		if(privateKey.startsWith("file:///")) {
			readBytes = Files.readAllBytes(Paths.get(privateKey.substring("file:///".length())));
		}else {
			readBytes = privateKey.getBytes();	
		}
		
		byte[] keyBytes = Base64.getDecoder().decode(readBytes);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");	    
		return kf.generatePrivate(spec);
	}
}
