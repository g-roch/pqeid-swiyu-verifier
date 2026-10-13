package ch.admin.bj.swiyu.verifier.domain.statuslist;

import ch.admin.bj.swiyu.jwtutil.SignatureVerifiers;
import ch.admin.bj.swiyu.verifier.common.exception.VerificationException;
import ch.admin.bj.swiyu.verifier.service.oid4vp.test.fixtures.KeyFixtures;
import ch.admin.bj.swiyu.verifier.service.publickey.IssuerPublicKeyLoader;
import ch.admin.bj.swiyu.verifier.service.statuslist.StatusListResolverAdapter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Map;
import java.util.Set;

import static ch.admin.bj.swiyu.verifier.service.oid4vp.test.fixtures.StatusListGenerator.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** PQEID: status-list signatures are checked through the verifier's algorithm policy. */
class TokenStatusListReferencePolicyTest {

    private static final String ISSUER = "TEST_ISSUER_ID";
    private static final String KID = "TEST_ISSUER_ID#key-1";

    private final StatusListResolverAdapter resolver = mock(StatusListResolverAdapter.class);
    private final IssuerPublicKeyLoader keyLoader = mock(IssuerPublicKeyLoader.class);

    @BeforeAll
    static void registerBc() {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    private TokenStatusListReference reference(Set<JWSAlgorithm> accepted) {
        return new TokenStatusListReference(resolver, Map.of("idx", 4, "uri", SPEC_SUBJECT),
                keyLoader, ISSUER, 204800, accepted);
    }

    /** The status list signed with {@code key}, served by the resolver; {@code key}'s public part from the DID. */
    private void serveStatusListSignedWith(JWK key) throws Exception {
        when(resolver.resolveStatusList(SPEC_SUBJECT)).thenReturn(
                createTokenStatusListTokenVerifiableCredential(SPEC_STATUS_LIST, key, ISSUER, KID));
        when(keyLoader.loadJWK(ISSUER, KID)).thenReturn(key.toPublicJWK());
    }

    @Test
    void contractPolicy_rejectsMldsa44StatusList() throws Exception {
        // Arrange
        serveStatusListSignedWith(KeyFixtures.issuerMLDSAKey());

        // Act / Assert
        assertThrows(VerificationException.class,
                () -> reference(Set.of(JWSAlgorithm.ML_DSA_65_ES256)).verifyStatus());
    }
     @Test
    void compositeSignedStatusList_verifies() throws Exception {
        // Arrange
        var kp = KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC").generateKeyPair();
        serveStatusListSignedWith(CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate()));

        // Act / Assert
        assertDoesNotThrow(() -> reference(SignatureVerifiers.MIGRATION_DEFAULT).verifyStatus());
    }
}