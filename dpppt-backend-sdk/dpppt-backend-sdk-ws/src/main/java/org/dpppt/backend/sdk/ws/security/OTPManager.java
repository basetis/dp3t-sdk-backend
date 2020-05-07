package org.dpppt.backend.sdk.ws.security;

import java.security.InvalidParameterException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class OTPManager {

	private static OTPManager otpManager;
	
	private Map<String,OTPPassConfiguration> map = new ConcurrentHashMap<>();
	
	public static OTPManager getInstance() {
		
		if(otpManager==null) {
			synchronized(OTPManager.class) {
				if(otpManager == null) {
					otpManager = new OTPManager();
				}
			}
		}
		
		return otpManager;
	}
	
	public void setPassword(String password) {
		map.put(password, new OTPPassConfiguration(password));
	}
	
	public void checkPassword(String password) {
		if(map.containsKey(password)) {
			validatePassword(map.get(password));
		}else {
			throw new InvalidParameterException("Incorrect Password");
		}
	}
	
	private void validatePassword(OTPPassConfiguration password) {
		
		if(password.isUsed()) {
			throw new InvalidParameterException("Password already used");
		}
		
		password.setUsed(true);
		password.setAttempts(password.getAttempts()+1);
		// Expired time 30min
		if((password.getCreationMils()+1*60000)<System.currentTimeMillis()) {
			throw new InvalidParameterException("Password expired");
		}
		
	}
}
