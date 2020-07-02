import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.util.Base64Utils;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class KeysTest {

	public static void main(String[] args) throws Exception {
		
		KeyPair kp = Keys.keyPairFor(SignatureAlgorithm.ES256);
		String strPrivateKey = Base64.encodeToString(kp.getPrivate().getEncoded());
		System.out.println(strPrivateKey);
		String privateFilePath = "C:\\Users\\josevincente.marin\\Documents\\Projects\\Dp3t\\github\\dp3t-sdk-backend\\dpppt-backend-sdk\\conf_var\\keys\\privateKey.pem";
		FileUtils.writeStringToFile(new File(privateFilePath), strPrivateKey);
		
		String publicFilePath = "C:\\Users\\josevincente.marin\\Documents\\Projects\\Dp3t\\github\\dp3t-sdk-backend\\dpppt-backend-sdk\\conf_var\\keys\\publicKey.pem";
		String strPublicKey = getPublicKeyAsPEM(kp.getPublic());
		System.out.println(strPublicKey);
		FileUtils.writeStringToFile(new File(publicFilePath), strPublicKey);

		KeyPair kp2 = getKeyPair(strPrivateKey, strPublicKey);
		System.out.println(getPrivateKeyAsPEM(kp2.getPrivate()));
		System.out.println(getPublicKeyAsPEM(kp2.getPublic()));
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
	
	private static KeyPair getKeyPair(String pemPrivateKey, String pemPublicKey) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		
		byte[] rawPrivateKey = getBytesFromPem(pemPrivateKey);
		byte[] rawPublicKey = getBytesFromPem(pemPublicKey);
		
    	KeyFactory kf = KeyFactory.getInstance("EC"); // or "EC" or whatever
    	PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(rawPrivateKey));
    	PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(rawPublicKey));

    	return new KeyPair(publicKey, privateKey);
	}
	
	private static byte[] getBytesFromPem(String pemKey) throws IOException {
		
		byte[] decodedPk = Base64Utils.decodeFromUrlSafeString(pemKey);
    	StringReader reader = new StringReader(new String(decodedPk));
    	PemReader pemReader = new PemReader(reader);
    	PemObject pemObject = pemReader.readPemObject();
    	pemReader.close();
    	return pemObject.getContent();
	}
}
