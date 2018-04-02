package com.zsisic.poc.jwtverifier;

public class KeyReferences {

    public static final String PRIVATE_KEY = "jwtRS256.keys";
    public static final String PUBLIC_KEY = "jwtRS256.key.pub";
    public static final String PUBLIC_KEY_NO_HEADERS = "jwtRS256-no-key-headers.key.pub";

    public static final String PRIVATE_KEY_2 = "jwt-2-RS256.keys";
    public static final String PUBLIC_KEY_2 = "jwt-2-RS256.key.pub";

    public static final String PRIVATE_KEY_512 = "jwt-RS512.keys";
    public static final String PUBLIC_KEY_512 = "jwt-RS512.key.pub";

    /**
     * Header: {
     *	  "alg": "RS256",
     *	  "typ": "JWT"
     * }
     *
     * Payload: {
     *	  "sub": "1234567890",
     *	  "name": "John Doe",
     *	  "hello": "world"
     * }
     *
     */
    public static final String TEST_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaGVsbG8iOiJ3b3JsZCJ9.Hz0Q0nZG3tecgeokWskeFUp3YX6TEO3cxcEhcS3WK5x0Wcq2qMv3QgvxB7vwPmYY9oPc3QWhPXSSidkQWKFWdBejefRkrL6KmrpYvvuwW-plWWUXe3FoJSy9UkMbj5_XvwvQv_Ovjnl3VcIAXKURZIyLgIIUB3RcTi8iflWxloGbMbDrXqfcSTo28p0WoR3aeTDwkg7CrZLOv3q1t1lXfCdPIzg_ZpRxQwXivJSTYWC3vWXF2sfcXdfNc7cVTTUibVbliY7HUo88R4R5LCQU-4lIXSadNBhrPUPuuxN1zjPzCXSUTwudUcWfPyGhDwDkmDcXa_S11b4CY5wtsqqY0Q";


}
