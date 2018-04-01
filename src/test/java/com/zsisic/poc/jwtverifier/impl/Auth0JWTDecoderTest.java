package com.zsisic.poc.jwtverifier.impl;

import static org.junit.Assert.assertEquals;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.zsisic.poc.jwtverifier.PublicKeyReader;

public class Auth0JWTDecoderTest {
	
	/**
	 * Header: {
	 *	  "alg": "RS256",
	 *	  "typ": "JWT"
	 * }
	 * 
	 * Payload: {
	 *	  "sub": "1234567890",
	 *	  "name": "John Doe",
	 *	  "admin": true,
	 *	  "iat": 1516239022,
	 *	  "hello": "bar"
	 * }
	 * 
	 */
	private static final String TEST_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiaGVsbG8iOiJ3b3JsZCJ9.Ec0oZGlf53udLKZZDhHsuUBmkoW9_bHDQ4iJDHyK1jllfn_xJzJNS2AZ7MJ5LCV5QWZCjE8REldUqX6MTu-VnP0hvYfe5yvMhOLKlMaFxSnVeQbBI98cco9e8yKd_g3teTS6P-fCA7Msm93emQCRBBnYlvoj2dVU6Yet4gYbL1gTyew4NY4egh_4hnmOW3L8R40CXfbwaJ1ZyUGC7o4cSopqYKmOeXOhPdH5OhLCyTqFlpJ0eqCLJDIof437I613jaFDAsQ6RBIdF0KapQnBaQ3FF31p2F9UdAYo0JKtS5E3vmBjynkHnRO9KVpZ_N5_JtrJ0CrS7KQM1fLge3XHWdiRgwtx4ga_JQ7fW5cyLbj9lYtOXmuoNxCh0p6zCyStxmB_Ez_InJJWhyLdIur6hCirhm8LPsFQeCVntzUlKEAgs2d43Gk7SH3KTbm-XGl-EcZh3JnmTEiaqBpx331MP42RRUfxBoVRXYrPyfHkAdx7hT3axbAN5TGZEXOpE3rHzCvqUSTYM7dcadzLNJrVEkRTJdwOqRLyIGLJ-tqihvTIPto2sCIE4UGZlz-O5uCRL0XvpJY2pT6iwkrPP-3mlMcvB9HhL8WxcDlqgv25UZsQJH0uT5v-BfrOqClqPV4WkaaX3csnLxe4mE4hzTFP9NIsDmAfXBwqraTBHpKRJrM";

	@Test
	public void testTokenVerificationAndClaimExtraction() throws Exception {
		JWTVerifier verifier = getVerifier("jwtRS256.key.pub-no-headers");
		
		DecodedJWT decoded = verifier.verify(TEST_TOKEN);
		String value = decoded.getClaim("hello").asString();
		assertEquals("world",  value);
	}
	
	@Test
	public void testTokenVerificationAndClaimExtraction_WithPublicKeyHeaders() throws Exception {
		JWTVerifier verifier = getVerifier("jwtRS256.key.pub");
		
		DecodedJWT decoded = verifier.verify(TEST_TOKEN);
		String value = decoded.getClaim("hello").asString();
		assertEquals("world",  value);
	}
	
	@Test(expected = SignatureVerificationException.class)
	public void testTokenverification_withDifferentPublicKey_shouldFail() throws Exception {
		JWTVerifier verifier = getVerifier("jwt-2-RS256.key.pub");
		
		DecodedJWT decoded = verifier.verify(TEST_TOKEN);
		decoded.getClaim("hello").asString();
	}
	
	@Test(expected = SignatureVerificationException.class)
	public void testTokenverification_WithPayloadModified_shouldFail() throws Exception {

		List<String> jwtSections = Splitter.on(".").splitToList(TEST_TOKEN);
		String payload = new String( Base64.decode(jwtSections.get(1)));
		String modifiedpayload = new String(Base64.encode(payload.replace("world", "bar").getBytes()));
		String tokenWithModifiedPayload = Joiner.on(".").join(jwtSections.get(0), modifiedpayload, jwtSections.get(2));
		
		JWTVerifier verifier = getVerifier("jwtRS256.key.pub");
		verifier.verify(tokenWithModifiedPayload);
	}
	
	private JWTVerifier getVerifier(String publicKeyPath) throws Exception {
		PublicKey publicKey = PublicKeyReader.get(publicKeyPath);
		Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);
		return JWT.require(algorithm).build();
	}

}
