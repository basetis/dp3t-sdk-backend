/**
 * This file only serves as an example on how to get keys in the right encoding. 
 * 
 * DO NOT USE THEM IN PRODUCTION UNLESS THE KEYSPECS ARE OK FOR YOU
 */
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.dpppt.backend.sdk.ws.util.KeyHelper;
import org.springframework.util.Base64Utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class GenerateKeyPair{
    public static void main(String[] args) throws Exception {
//		Security.setProperty("crypto.policy", "unlimited");
//		KeyPairGenerator generator =  KeyPairGenerator.getInstance("RSA");
//		KeyPair pair = generator.genKeyPair();
//		PrivateKey privateKey = pair.getPrivate();
//		PublicKey publicKey = pair.getPublic();
//		FileOutputStream outputStream = new FileOutputStream("generated_pub.pem");
//		outputStream.write(Base64.getEncoder().encode(publicKey.getEncoded()));
//        outputStream.close();
//        
//        outputStream = new FileOutputStream("generated_private.pem");
//		outputStream.write(Base64.getEncoder().encode(privateKey.getEncoded()));
//		outputStream.close();
    	
//    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	KeyPair kp = Keys.keyPairFor(SignatureAlgorithm.ES256);
//    	String filePath = "C:\\Users\\josevincente.marin\\Documents\\Projects\\Dp3t\\github\\dp3t-sdk-backend\\dpppt-backend-sdk\\conf_var\\keys\\privateKey.pem";
//    	String publicFilePath = "C:\\Users\\josevincente.marin\\Documents\\Projects\\Dp3t\\github\\dp3t-sdk-backend\\dpppt-backend-sdk\\conf_var\\keys\\publicKey.pem";
//    	
//    	String privateTest = getPrivateKeyAsPEM(kp.getPrivate());
//    	saveFile(privateTest, filePath);
//    	System.out.println(privateTest);
    	
//    	String privateFromFile = readFile(filePath);
//    	KeyPair privateFromProp = getPairFromPEM(privateFromFile);
//    	String sentPublicKey = getPublicKeyAsPEM(privateFromProp.getPublic());
//    	System.out.println(sentPublicKey);
    	
    	
    	String publicKeyBase64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRThVSlhHV1BaanVOVys0SXFRU2hZL2VZeFFqNjgNCkZRZ1FBcHpldTlZUFBySkZxOElPOUJpeUFXYVA2KzNmTExPNHZ6OXVtbng1ZGxaZjh6QnQwekdoNGc9PQ0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t";
    	String signature = "eyJhbGciOiJFUzI1NiJ9.eyJjb250ZW50LWhhc2giOiJLN2xEd0pIU2VKa2hJYm1WODdHb0JRK0FaQ2pZU3Y3M1dGRTZzZ2ZyVlowPSIsImhhc2gtYWxnIjoic2hhLTI1NiIsImlzcyI6ImRwM3QiLCJpYXQiOjE1OTI5MjI1MTIsImV4cCI6MTU5NDczNjkxMiwib3RwIjoiNjcxOTg4MjQyODY0In0.1-CeRRqfND3jBv-ZYtODa7ZvdJtOSYKyQD1sm7V0Ii9ATFxAkphUrynnrqyF2WP5WidXsUgrXLu7rgR70xm8jw";
    	
    	try {
    		
    		KeyPair kp2 = Keys.keyPairFor(SignatureAlgorithm.ES256);
    		String pemPublicKey = getPublicKeyAsPEM(kp2.getPublic());
    		byte[] pubkeyRaw = Base64Utils.decodeFromUrlSafeString(pemPublicKey.replaceAll("-+(BEGIN|END) PUBLIC KEY-+", "").trim());
    		
    		PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pubkeyRaw));
    		
    		
			Jws<Claims> claimsJws = Jwts.parserBuilder()
					.setSigningKey(publicKey)
					.build()
					.parseClaimsJws(signature);
			//String hash64 = claimsJws.getBody().get("content-hash", String.class);
			//body = new String(Base64.getDecoder().decode(hash64), StandardCharsets.UTF_8);
		} catch (io.jsonwebtoken.security.SignatureException e) {
			e.printStackTrace();
		}
    }
    
    
    private static String getPublicKeyAsPEM(PublicKey pk) throws IOException {
		StringWriter writer = new StringWriter();
		PemWriter pemWriter = new PemWriter(writer);
		pemWriter.writeObject(new PemObject("PUBLIC KEY", pk.getEncoded()));
		pemWriter.flush();
		pemWriter.close();
		return Base64Utils.encodeToUrlSafeString(writer.toString().trim().getBytes());
	}
    
    private static String getPrivateKeyAsPEM(PrivateKey pk) throws IOException {
		StringWriter writer = new StringWriter();
		PemWriter pemWriter = new PemWriter(writer);
		pemWriter.writeObject(new PemObject("PRIVATE KEY", pk.getEncoded()));
		pemWriter.flush();
		pemWriter.close();
		return Base64Utils.encodeToUrlSafeString(writer.toString().trim().getBytes());
	}
    
    private static void saveFile(String pk, String filePath) throws IOException {
    	
    	FileUtils.writeStringToFile(new File(filePath), pk);

	}
    
    private static String readFile(String filePath) throws IOException {
//    	String privateKey = FileUtils.readFileToString(new File(filePath));
//    	return privateKey;
    	InputStream in = new FileInputStream(filePath);
		return IOUtils.toString(in);
    }
    
    private static KeyPair getPairFromPEM(String pk){
    	KeyPair toReturn = null;
    	
		try {
			byte[] decodedPk = Base64Utils.decodeFromUrlSafeString(pk);
	    	StringReader reader = new StringReader(new String(decodedPk));
	    	PemReader pemReader = new PemReader(reader);
	    	PemObject pemObject = pemReader.readPemObject();
	    	
	    	pemReader.close();
	    	
	    	ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
//			ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			
			BigInteger privateKey = new BigInteger(1, pemObject.getContent());
	    	ECPrivateKeySpec keySpec = new ECPrivateKeySpec(privateKey, ecParameterSpec);
	    	KeyFactory kf = KeyFactory.getInstance("EC", "BC");
	    	ECPrivateKey pv = (ECPrivateKey)kf.generatePrivate(keySpec);
	    	
	    	
	    	ECPoint Q = ecParameterSpec.getG().multiply(pv.getD());
	    	byte[] publicDerBytes = Q.getEncoded(false);
	    	ECPoint point = ecParameterSpec.getCurve().decodePoint(publicDerBytes);
	    	ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecParameterSpec);
	    	ECPublicKey pb = (ECPublicKey) kf.generatePublic(pubSpec);
	    	toReturn = new KeyPair((PublicKey)pb, (PrivateKey)pv);

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return toReturn;
    }
}