package com.zsisic.poc.jwtverifier.impl;

import static com.zsisic.poc.jwtverifier.KeyReferences.TEST_TOKEN;
import static org.junit.Assert.assertEquals;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.zsisic.poc.jwtverifier.KeyReferences;
import com.zsisic.poc.jwtverifier.PublicKeyReader;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

public class Auth0JWTDecoderTest {
	

	@Test
	public void testTokenVerificationAndClaimExtraction() throws Exception {
		JWTVerifier verifier = getVerifier(KeyReferences.PUBLIC_KEY_NO_HEADERS);
		
		DecodedJWT decoded = verifier.verify(TEST_TOKEN);
		String value = decoded.getClaim("hello").asString();
		assertEquals("world",  value);
	}
	
	@Test
	public void testTokenVerificationAndClaimExtraction_WithPublicKeyHeaders() throws Exception {
		JWTVerifier verifier = getVerifier(KeyReferences.PUBLIC_KEY);
		
		DecodedJWT decoded = verifier.verify(TEST_TOKEN);
		String value = decoded.getClaim("hello").asString();
		assertEquals("world",  value);
	}
	
	@Test(expected = SignatureVerificationException.class)
	public void testTokenVerification_withDifferentPublicKey_shouldFail() throws Exception {
		JWTVerifier verifier = getVerifier(KeyReferences.PUBLIC_KEY_2);
		
		DecodedJWT decoded = verifier.verify(TEST_TOKEN);
		decoded.getClaim("hello").asString();
	}

	@Test
	public void testTokenVerification_withDifferentPublicKeyStrength_shouldFail() throws Exception {
		JWTVerifier verifier = getVerifier(KeyReferences.PUBLIC_KEY);

		DecodedJWT decoded = verifier.verify(TEST_TOKEN);
		decoded.getClaim("hello").asString();
	}

	
	@Test(expected = SignatureVerificationException.class)
	public void testTokenVerification_WithPayloadModified_shouldFail() throws Exception {

		List<String> jwtSections = Splitter.on(".").splitToList(TEST_TOKEN);
		String payload = new String( Base64.decode(jwtSections.get(1)));
		String modifiedpayload = new String(Base64.encode(payload.replace("world", "bar").getBytes()));
		String tokenWithModifiedPayload = Joiner.on(".").join(jwtSections.get(0), modifiedpayload, jwtSections.get(2));
		
		JWTVerifier verifier = getVerifier(KeyReferences.PUBLIC_KEY);
		verifier.verify(tokenWithModifiedPayload);
	}
	
	private JWTVerifier getVerifier(String publicKeyPath) throws Exception {
		PublicKey publicKey = PublicKeyReader.get(publicKeyPath);
		Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);
		return JWT.require(algorithm).build();
	}

}
