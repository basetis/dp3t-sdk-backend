package org.dpppt.backend.sdk.ws.security;

public class OTPPassConfiguration {
	
	private String password;
	
	private int attempts;
	
	private boolean isUsed;
	
	private long creationMils;
	
	public OTPPassConfiguration(String password) {
		this.password = password;
		creationMils = System.currentTimeMillis();
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public int getAttempts() {
		return attempts;
	}

	public void setAttempts(int attempts) {
		this.attempts = attempts;
	}

	public boolean isUsed() {
		return isUsed;
	}

	public void setUsed(boolean isUsed) {
		this.isUsed = isUsed;
	}

	public long getCreationMils() {
		return creationMils;
	}

	public void setCreationMils(long creationMils) {
		this.creationMils = creationMils;
	}	
	

}
