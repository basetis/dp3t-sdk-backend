package org.dpppt.backend.sdk.ws.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class FrontalSecurityService {
	
	@Value("#{${back.office.users}}")
	private Map<String, String> users;
	
	@Value("${ws.app.jwt.privatekey}")
	private String jwtPrivate;

	public FrontalResponseLogin validateUser(FrontalUserLogin userToValidate) {
		
		FrontalResponseLogin response = new FrontalResponseLogin();
		
		if(userToValidate==null || users.isEmpty() || jwtPrivate.isEmpty()) {
			response.setError("Internal error");
			return response;
		}
		
		if(userToValidate.getUsername()==null) {
			response.setError("Username is empty");
			return response;
		}
		
		if(userToValidate.getPassword()==null) {
			response.setError("Password is empty");
			return response;
		}
		
		if(!users.containsKey(userToValidate.getUsername())) {
			response.setError("User not found");
			return response;
		}
		
		try {
			String generatedPwd = generatePassword(userToValidate.getPassword());
			if(!generatedPwd.equals(users.get(userToValidate.getUsername()))) {
				response.setError("Wrong Password");
				return response;
			}
			
			String token = generateJWTToken();
			response.setToken(token);
			response.setError("Success Login");
		} catch (Exception e) {
			e.printStackTrace();
			response.setError("Internal error");
			return response;
		}
		
		return response;
	}
	

	private String generatePassword(String password) throws Exception {
		
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] encodedhash = digest.digest(
				password.getBytes(StandardCharsets.UTF_8));
		StringBuilder b = new StringBuilder();
		b.append(Base64.getEncoder().encodeToString(encodedhash));
		
		return b.toString().replaceAll(",", "+");
	}
	
	
	public String generateJWTToken() throws Exception{
		
		JWTGenerator jwtGenerator = new JWTGenerator(jwtPrivate);
		OffsetDateTime expiresAt = OffsetDateTime.now().withOffsetSameInstant(ZoneOffset.UTC).plusMinutes(60);
		String jwtToken = jwtGenerator.createToken(expiresAt, 0);
		
		return "Bearer " + jwtToken;
	}

}
