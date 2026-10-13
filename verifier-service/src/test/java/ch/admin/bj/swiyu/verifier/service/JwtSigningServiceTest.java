package ch.admin.bj.swiyu.verifier.service;

import ch.admin.bj.swiyu.verifier.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.verifier.common.config.HSMProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.crypto.CompositeVerifier;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.MLDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** PQEID: the request-object header alg follows the configured key. */
class JwtSigningServiceTest {

    private JwsSignatureFacade facade;
    private JwtSigningService sut;

    @BeforeAll
    static void registerBc() {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    @BeforeEach
    void setUp() {
        ApplicationProperties props = mock(ApplicationProperties.class);
        when(props.getHsm()).thenReturn(mock(HSMProperties.class)); // read by toSignatureConfiguration
        facade = mock(JwsSignatureFacade.class);
        sut = new JwtSigningService(props, facade);
    }

    private SignedJWT signWith(JWSSigner signer) throws Exception {
        when(facade.createSigner(any(), any(), any())).thenReturn(signer);
        return sut.signJwt(new JWTClaimsSet.Builder().issuer("did:example:v").build(),
                null, null, "did:example:v#auth-key-01");
    }

    @Test
    void signJwt_mldsa44Key_headerIsMlDsa44() throws Exception {
        // Arrange
        MLDSAKey key = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).generate();

        // Act
        SignedJWT jwt = signWith(new MLDSASigner(key));

        // Assert
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ML_DSA_44);
        assertThat(jwt.verify(new MLDSAVerifier(key.toPublicJWK()))).isTrue();
    }

    @Test
    void signJwt_compositeKey_headerIsComposite() throws Exception {
        // Arrange
        KeyPair kp = KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC")
                .generateKeyPair();
        CompositeMLDSAKey key = CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate());

        // Act
        SignedJWT jwt = signWith(new CompositeSigner(key));

        // Assert
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ML_DSA_65_ES256);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("did:example:v#auth-key-01");
        assertThat(jwt.verify(new CompositeVerifier(key.toPublicJWK()))).isTrue();
    }
}

