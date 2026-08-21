package ch.admin.bj.swiyu.verifier.service.oid4vp.test.fixtures;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.experimental.UtilityClass;

import java.security.interfaces.ECPublicKey;
import java.util.Base64;

/**
 * Fixtures for public / private keys we can use them in tests.
 */
@UtilityClass
public class KeyFixtures {
    private static final String DEFAULT_ISSUER_PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIDqMm9PvL4vpyFboAwaeViQsH30CkaDcVtRniZPezFxpoAoGCCqGSM49\nAwEHoUQDQgAEQgjeqGSdu+2jq8+n78+6fXk2Yh22lQKBYCnu5FWPvKtat3wFEsQX\nqNHYgPXBxWmOBw5l2PE/gUDUJqGJSc1LuQ==\n-----END EC PRIVATE KEY-----";

    // PQEID: real ML-DSA-44 private key, generated with `openssl genpkey -algorithm ML-DSA-44`
    // (OpenSSL 3.5+ has native ML-DSA support). NOT runtime-verified against BouncyCastle's
    // KeyFactory in the nimbus fork yet (no local Maven/JDK toolchain in the environment that
    // generated it) - confirm via `mvn test` that MLDSAKey correctly parses this PEM.
    private static final String DEFAULT_ISSUER_MLDSA_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n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\n-----END PRIVATE KEY-----";

    /**
     * Returns a private key of an issuer as ECKey.
     */
    public static ECKey issuerKey() {
        return toEcKey(DEFAULT_ISSUER_PRIVATE_KEY);
    }

    /**
     * PQEID: returns a private ML-DSA-44 key of an issuer.
     */
    public static MLDSAKey issuerMLDSAKey() {
        try {
            return JWK.parseFromPEMEncodedObjects(DEFAULT_ISSUER_MLDSA_PRIVATE_KEY).toMLDSAKey();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * PQEID: returns a freshly generated ML-DSA-44 holder key.
     */
    public static MLDSAKey holderMLDSAKey() {
        try {
            return new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).generate();
        } catch (JOSEException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Returns the public key of the issuer above as byte array.
     */
    public static byte[] issuerPublicKeyEncoded() throws JOSEException {
        return issuerKey().toPublicKey().getEncoded();
    }

    /**
     * Returns the public key of the issuer above as base64 url encoded multikey.
     */
    public static String issuerPublicKeyAsMultibaseKey() {
        try {
            return toBase64UrlEncodedMultibaseKey(issuerKey().toECPublicKey());
        } catch (JOSEException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Returns the JSON Web Key (JWK) of the issuers public key (as json, not encoded).
     */
    public static String issuerPublicKeyAsJsonWebKey() {
        return issuerKey().toPublicJWK().toJSONString();
    }

    private static ECKey toEcKey(String pemEncodedObjects) {
        try {
            return JWK.parseFromPEMEncodedObjects(pemEncodedObjects).toECKey();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private static String toBase64UrlEncodedMultibaseKey(ECPublicKey publicKey) {
        byte[] encodedKey = publicKey.getEncoded();
        String base64UrlEncodedKey = Base64.getUrlEncoder().encodeToString(encodedKey);
        return "u" + base64UrlEncodedKey;
    }

    public static ECKey holderKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate();
        } catch (JOSEException e) {
            throw new AssertionError(e);
        }
    }
}
