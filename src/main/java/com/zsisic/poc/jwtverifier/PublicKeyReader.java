package com.zsisic.poc.jwtverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.util.encoders.Base64;

public class PublicKeyReader {
	
	private static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
	private static final String PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";
	private static final String EMPTY_STRING = "";

	public static PublicKey get(String filename) throws Exception {
		Path path = Paths.get(ClassLoader.getSystemResource(filename).toURI());       
			   
		final String publicKeyString = new String(Files.readAllBytes(path))
				.replace(PUBLIC_KEY_HEADER, EMPTY_STRING)
				.replace(PUBLIC_KEY_FOOTER, EMPTY_STRING);

		X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.decode(publicKeyString));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
}
