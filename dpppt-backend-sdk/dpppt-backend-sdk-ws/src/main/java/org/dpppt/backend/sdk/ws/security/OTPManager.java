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
	
	public void checkPassword(String password, long expireTime) {
		if(map.containsKey(password)) {
			validatePassword(map.get(password), expireTime);
		}else {
			throw new InvalidParameterException("Incorrect Password");
		}
	}
	
	private void validatePassword(OTPPassConfiguration password, long expireTime) {
		
		if(password.isUsed()) {
			throw new InvalidParameterException("Password already used");
		}
		
		password.setUsed(true);
		password.setAttempts(password.getAttempts()+1);
		long expiredMilsTime = expireTime*60000;
		if((password.getCreationMils()+expiredMilsTime)<System.currentTimeMillis()) {
			throw new InvalidParameterException("Password expired");
		}
		
	}
}
