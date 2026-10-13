package ch.admin.bj.swiyu.verifier.infrastructure.health;

import ch.admin.bj.swiyu.jwtutil.SignatureVerifiers;
import ch.admin.bj.swiyu.verifier.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.verifier.service.JwtSigningService;
import ch.admin.bj.swiyu.verifier.service.publickey.DidResolverFacade;
import ch.admin.eid.did_sidekicks.Jwk;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;

/** PQEID: the health check verifies our own signature against our DID key, via the policy. */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SigningKeyVerificationHealthCheckerPolicyTest {

    private static final String DID = "did:example:123";
    private static final String VERIFICATION_METHOD = DID + "#key-1";

    @Mock private DidResolverFacade didResolverFacade;
    @Mock private ApplicationProperties applicationProperties;
    @Mock private JwtSigningService jwtSigningService;
    @Mock private HealthCheckProperties healthCheckProperties;
    @Mock private Jwk jwk;

    private SigningKeyVerificationHealthChecker checker;

    @BeforeAll
     static void registerBc() {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    @BeforeEach
    void setUp() {
        checker = new SigningKeyVerificationHealthChecker(didResolverFacade, applicationProperties,
                jwtSigningService, healthCheckProperties);
        when(healthCheckProperties.isSigningKeyVerificationEnabled()).thenReturn(true);
        when(applicationProperties.getSigningKeyVerificationMethod()).thenReturn(VERIFICATION_METHOD);
        when(applicationProperties.acceptedSignatureJwsAlgorithms())
                .thenReturn(SignatureVerifiers.MIGRATION_DEFAULT);
    }

    /** Our signing service signs with {@code key}; our DID publishes {@code key}'s public part (AKP JWK). */
    private void configure(JWK key, JWSSigner signer) throws Exception {
        JWSAlgorithm alg = (JWSAlgorithm) key.getAlgorithm();
        when(jwtSigningService.signJwt(any(), isNull(), isNull(), anyString())).thenAnswer(inv -> {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(alg).keyID(VERIFICATION_METHOD).build(),
                    inv.getArgument(0, JWTClaimsSet.class));
            jwt.sign(signer);
             return jwt;
        });
        when(didResolverFacade.resolveDid(DID, "key-1")).thenReturn(jwk);
        when(jwk.getKty()).thenReturn("AKP");
        when(jwk.getAlg()).thenReturn(alg.getName());
        when(jwk.getPubKey()).thenReturn((String) key.toPublicJWK().toJSONObject().get("pub"));
        when(jwk.getKid()).thenReturn("key-1");
    }

    private Health check() {
        Health.Builder builder = Health.up();
        checker.performCheck(builder);
        return builder.build();
    }

    @Test
    void mldsa44Key_reportsUp() throws Exception {
        // Arrange
        MLDSAKey key = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).generate();
        configure(key, new MLDSASigner(key));

        // Act / Assert
        assertThat(check().getStatus()).isEqualTo(Status.UP);
    }

    @Test
    void compositeKey_reportsUp() throws Exception {
        // Arrange
        var kp = KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC").generateKeyPair();
        CompositeMLDSAKey key = CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate());
        configure(key, new CompositeSigner(key));

        // Act / Assert
        assertThat(check().getStatus()).isEqualTo(Status.UP);
    }

     /** Contract policy + an ML-DSA-44 DID key: DOWN, and the reason is reported. */
    @Test
    void keyOutsidePolicy_reportsDownWithReason() throws Exception {
        // Arrange
        when(applicationProperties.acceptedSignatureJwsAlgorithms())
                .thenReturn(Set.of(JWSAlgorithm.ML_DSA_65_ES256));
        MLDSAKey key = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).generate();
        configure(key, new MLDSASigner(key));

        // Act
        Health health = check();

        // Assert
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails().get("signingError").toString()).contains("not accepted");
    }
}