package com.zsisic.poc.jwtverifier.impl;

import static com.zsisic.poc.jwtverifier.KeyReferences.TEST_TOKEN;
import static org.junit.Assert.assertEquals;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.zsisic.poc.jwtverifier.KeyReferences;
import org.apache.commons.collections4.MapUtils;
import org.junit.Test;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.codec.Codecs;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;


/**
 * This is pure spring security jwt  implementation of jwt token validation and extraction
 *
 *  + It uses the token alg header to validate the type of algorithm
 *  + hides security implementation
 *  + verifies public key
 *
 *  - abstraction of implementation, works until it does not :) (common spring problem)
 */
public class SpringSecurityJWTDecoderTest {
	

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	private static final TypeReference<HashMap<String, Object>> TYPE_REF
			= new TypeReference<HashMap<String, Object>>() {};


	@Test
	public void testTokenVerificationAndClaimExtraction_WithPublicKeyHeaders() throws Exception {
		Map<String, Object> claims = verifyAndGetClaims(TEST_TOKEN, KeyReferences.PUBLIC_KEY);
		String value = MapUtils.getString(claims, "hello");
		assertEquals("world",  value);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTokenVerificationAndClaimExtraction_withoutPublicHeaders_fails() throws Exception {
		Map<String, Object> claims = verifyAndGetClaims(TEST_TOKEN, KeyReferences.PUBLIC_KEY_NO_HEADERS);
		String value = MapUtils.getString(claims, "hello");
		assertEquals("world",  value);
	}
	
	@Test(expected = RuntimeException.class)
	public void testTokenVerification_withDifferentPublicKeyStrength_shouldFail() throws Exception {
		verifyAndGetClaims(TEST_TOKEN, KeyReferences.PUBLIC_KEY_512);
	}

	@Test(expected=InvalidSignatureException.class)
	public void testTokenVerification_withDifferentPublicKeyshouldFail() throws Exception {
		verifyAndGetClaims(TEST_TOKEN, KeyReferences.PUBLIC_KEY_2);
	}
	
	@Test(expected = InvalidSignatureException.class)
	public void testTokenVerification_WithPayloadModified_shouldFail() throws Exception {
		List<String> jwtSections = Splitter.on(".").splitToList(TEST_TOKEN);

		String payload = new String(Codecs.b64Decode(jwtSections.get(1).getBytes()));
		String modifiedPayload = new String(Codecs.b64Encode((payload.replace("world", "bar").getBytes())));
		String tokenWithModifiedPayload = Joiner.on(".").join(jwtSections.get(0), modifiedPayload, jwtSections.get(2));

		verifyAndGetClaims(tokenWithModifiedPayload, KeyReferences.PUBLIC_KEY);
	}

	private Map<String, Object> verifyAndGetClaims(String token, String publicKeyLocation) throws Exception {
		SignatureVerifier verifier = getVerifier(publicKeyLocation);
		Jwt jwt = JwtHelper.decodeAndVerify(token, verifier);
		return OBJECT_MAPPER.readValue(jwt.getClaims(), TYPE_REF);
	}

	private SignatureVerifier getVerifier(String publicKeyPath) throws Exception {
		return new RsaVerifier(readKeyAsString(publicKeyPath));
	}

	private String readKeyAsString(String keyFileName) throws Exception {
		Path path = Paths.get(ClassLoader.getSystemResource(keyFileName).toURI());
		return new String(Files.readAllBytes(path));
	}
}
