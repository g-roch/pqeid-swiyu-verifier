package ch.admin.bj.swiyu.verifier;

import ch.admin.bj.swiyu.didresolveradapter.DidResolverException;
import ch.admin.bj.swiyu.verifier.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.verifier.domain.management.ManagementRepository;
import ch.admin.bj.swiyu.verifier.domain.management.ResponseModeType;
import ch.admin.bj.swiyu.verifier.dto.VPApiVersion;
import ch.admin.bj.swiyu.verifier.dto.management.*;
import ch.admin.bj.swiyu.verifier.service.management.fixtures.ApiFixtures;
import ch.admin.bj.swiyu.verifier.service.oid4vp.test.fixtures.DidDocFixtures;
import ch.admin.bj.swiyu.verifier.service.oid4vp.test.fixtures.KeyFixtures;
import ch.admin.bj.swiyu.verifier.service.oid4vp.test.mock.SDJWTCredentialMock;
import ch.admin.bj.swiyu.verifier.service.publickey.DidResolverFacade;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MLDSAVerifier;
import com.nimbusds.jose.crypto.XWingEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.XWingKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = Application.class)
@Nested
@DisplayName("Blackbox Test")
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class BlackboxIT {
    // PQEID: ECDSA -> ML-DSA. Public counterpart of application-test.yml's "signing_key".
    private static final String PUBLIC_KEY = "{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"50Js8eyUoqJrGFp-OtOaOdyA3tKjpUytCkHTQjew8MfzsF_uCM607yS3SG0zaFh6W8JTKjb6Uoy7sjyeapZcpoHRRgbTHDycGrn28AY_AAHj0NDixwv-0wRC2vfXWD-QR0IAuGA91N779mHYojs3suGadxWUjMKs7v569YpXr2yljGIKWA8g0yK-lq0Jh40_ke00eJxtt5JQV1Nu_msllBH1GXR5n0YB0SplSsM4migemsqEoMWAeZHNJCQFdeiX3klr7NSm8jCSdfSx7xBQpBg49tLtcCZS2DxYEPr1lMJTBit6v7GBeH3a090QtxqlkoXtqZDZB7QKgwc-hQtAMLLDNRT3G2wZ1xCl5AobJ48ezAIY0Be6nVR5uwBnMDNqTKJyQpHICkYEsmsk-uaaMz_TTmIp0OyAGMuot97Y7ejlkDeho7F5gf0tnPCngrlY1o4BxIs7ep53VnPmFr8C3Qrw0x54jkNi0AiJWuilJrDstdwlnS8dZp9-u50XjUoYm-v_oGD1z-ubTJKdVOvz708oH5SIVTGr7q8NbJ5Zh8tpdtLuWhYwdrIEkcWzzcG3EXXXGTC-AGFs-dzmzuea9icw4hDAOdL9umbxxeMDhKuhSsDj5r6HgxHsWPVPiiqn-nXNjL57mW1H9ZJ5KFvU-CajBLoPV31ISxMXHeF63P15CEo2cS7lA-1co065uf4LsLK0P2YaTRxTqf6J3PDrDA_YihLOxLQYabPoLUSj_rXsWPbEnX1looB0eA8tCJj_swovD1OtJ0odClFFblZ2imFUqsb3MkkxPlaYCFno-_znZaHbtYV4qljg6-fTbARth9zJIkfL70pMtWR2Sa2z1ewfHz7mR9wTwy2W3STLoPaDMN6WeioDVGU0kKq2cSIahJoONgB3H4vJhPRCO1ZWaU4jqv5jCN8BJP4GBfXF9qiJjfOSfiKHIkmOH5CoUsvmg0Y0cfxyjPqaHPq8YgiOThWTBxYSQPPKb-ylrwRwpFUANaCkasIb3q7nzxXQxgqjUuS6wVNbP63XqtwOtl36Sy438VlOPStb37vo4wy6B_dsjzBZUKyCdlzc8liyMf2j2MvO6Tjje-8v1CP45ix0W4gNNzP3jyhgSkMCH6c5G8RrZOAgQA75B8J4QfYozRHJ4yBtmOaMZFKbQ-1U3jHUPUogQFxeoNZmaW8ObxFgp6oidIHNeyl8bbE5meIPpitCKASxo4x3jczmld5hqMh15pgUAvowrP2awJPqewCbkOV3KO5lQZZwslR-DWI52xcsPHT7wX0FejJyjNixASgMoCLssEAxdtq4Y9qkgD1mXm0GBf12Y8o70zRgbbc_Twt0yH9mgbvXz6EwASCF7B-x-ym2I0wrAIz2BhtlZDKLJNDQQXRZvRp7OmQ6N88KAHY9MKh0Lp2x0dBk8pf6UteUHuPNPU9HXH2bB-HX2cdvwib382VaMqYP35L44rXN_twwjo_OWv3auyFVPv1LgjwFnvfkj0c_59zjD0JVKep5BQ8CYElBea339RYGnVh8v64WQObbiBmyFvkAL1iCY8d1zeiiSE3yWcOxkAFzxTmDvSRjfWDCH6AjeFeTss57U8Ve6G8-04Hff7uwcFBgL-hhLN9SAWvNT1c88c_ZgJo6Re68HPGX4wzilGay9_irQ6VGR3COFTrFg66x5EziONJzKPw3wXcq5v9k8edQ8K44r2ftuVk-rZ6aPErSC8MZIG3eNEs2-to7qg7nbMkAEDRyfQ\"}";
    private static final String ACCEPTED_ISSUER = "did:example:12345";

    private static final String MANAGEMENT_BASE_URL = "/management/api/verifications";
    private static final String OID4VP_API_BASE_URL = "/oid4vp/api/request-object";
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private MockMvc mvc;

    @Autowired
    private ApplicationProperties applicationProperties;
    @MockitoBean
    private DidResolverFacade didResolverFacade;
    @Autowired
    private ManagementRepository managementEntityRepository;

    @ParameterizedTest
    @MethodSource("provideCreateDtosDirectPost")
    void testVerificationFlow_walletSendsValidCredential(CreateVerificationManagementDto createVerificationManagementDto) throws Exception {
        var createDto = objectMapper.writeValueAsString(createVerificationManagementDto);
        var createResponseDto = createVerificationRequest(createDto);

        var nonce = createResponseDto.requestNonce();
        var requestId = createResponseDto.id().toString();

        // Check status, should be pending
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));

        // Wallet retrieves Verifier Request
        var state = getStateFromVerificationRequest(requestId, nonce, ResponseModeType.DIRECT_POST);

        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));

        // Wallet checks verifier metadata
        assertDoesNotThrow(() -> mvc.perform(get("/oid4vp/api/openid-client-metadata.json")
                        .contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.client_id").value(applicationProperties.getClientIdWithPrefix()))
                .andExpect(jsonPath("$.vp_formats.jwt_vp.alg").value(JWSAlgorithm.ML_DSA_44.getName()))
                .andReturn());
        // Check status, should still be pending
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));

        // Wallet sends valid credential
        var vpToken = Map.of("identity_credential_dcql", List.of(createMockCredential(nonce)));
        var submissionData = objectMapper.writeValueAsString(vpToken);
        assertDoesNotThrow(() -> mvc.perform(post(String.format("%s/%s/response-data", OID4VP_API_BASE_URL, requestId))
                        .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                        .header("SWIYU-API-Version", VPApiVersion.V1.getValue())
                        .formField("state", state)
                        .formField("vp_token", submissionData))
                .andExpect(status().isOk())
        );
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.SUCCESS));

        // Wallet sends error response, status should not change
        assertDoesNotThrow(() -> mvc.perform(post(String.format("%s/%s/response-data", OID4VP_API_BASE_URL, requestId))
                        .header("SWIYU-API-Version", VPApiVersion.V1.getValue())
                        .formField("state", state)
                        .formField("error", "vp_formats_not_supported")
                        .formField("error_description", "I really don't want to"))
                .andExpect(status().isGone())
        );
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.SUCCESS));
    }

    @ParameterizedTest
    @MethodSource("provideCreateNestedDtosDirectPost")
    void testVerificationFlow_dcql_recursive(CreateVerificationManagementDto createVerificationManagementDto) throws Exception {
        var createDto = objectMapper.writeValueAsString(createVerificationManagementDto);
        var createResponseDto = createVerificationRequest(createDto);

        var nonce = createResponseDto.requestNonce();
        var requestId = createResponseDto.id().toString();

        // Check status, should be pending
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));

        // Wallet retrieves Verifier Request
        var state = getStateFromVerificationRequest(requestId, nonce, ResponseModeType.DIRECT_POST);

        // Wallet sends valid credential
        var cred = List.of(createMockCredential_rec(nonce));
        var vpToken = Map.of("identity_credential_dcql", cred);
        var submissionData = objectMapper.writeValueAsString(vpToken);
        assertDoesNotThrow(() -> mvc.perform(post(String.format("%s/%s/response-data", OID4VP_API_BASE_URL, requestId))
                        .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                        .header("SWIYU-API-Version", VPApiVersion.V1.getValue())
                        .formField("state", state)
                        .formField("vp_token", submissionData))
                .andExpect(status().isOk())
        );
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.SUCCESS));
    }

    @ParameterizedTest
    @MethodSource("provideCreateDtosDirectPost")
    void testVerificationFlow_walletSendsError(CreateVerificationManagementDto createVerificationManagementDto) throws Exception {
        var createDto = objectMapper.writeValueAsString(createVerificationManagementDto);
        var createResponseDto = createVerificationRequest(createDto);

        var nonce = createResponseDto.requestNonce();
        var requestId = createResponseDto.id().toString();

        // Check status, should be pending
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));

        // Wallet retrieves Verifier Request
        var state = getStateFromVerificationRequest(requestId, nonce, ResponseModeType.DIRECT_POST);

        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));
        // Wallet checks verifier metadata
        assertDoesNotThrow(() -> mvc.perform(get("/oid4vp/api/openid-client-metadata.json")
                        .contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.client_id").value(applicationProperties.getClientIdWithPrefix()))
                .andExpect(jsonPath("$.vp_formats.jwt_vp.alg").value(JWSAlgorithm.ML_DSA_44.getName()))
                .andReturn());
        // Check status, should still be pending
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));

        // Wallet sends error response
        assertDoesNotThrow(() -> mvc.perform(post(String.format("%s/%s/response-data", OID4VP_API_BASE_URL, requestId))
                        .formField("error", "vp_formats_not_supported")
                        .formField("state", state)
                        .formField("error_description", "I really don't want to"))
                .andExpect(status().isOk())
        );
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.FAILED));

        // Wallet sends valid credential, should be rejected
        var vpToken = createMockCredential(nonce);
        assertDoesNotThrow(() -> mvc.perform(post(String.format("%s/%s/response-data", OID4VP_API_BASE_URL, requestId))
                        .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                        .formField("vp_token", vpToken))
                .andExpect(status().isBadRequest())
        );
        // Status should not have changed, status should not change
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.FAILED));
    }

    @ParameterizedTest
    @MethodSource("provideCreateDtosDirectPostJwt")
    void testVerificationFlowDirectPostJWT(CreateVerificationManagementDto createVerificationManagementDto) throws Exception {
        var createDto = objectMapper.writeValueAsString(createVerificationManagementDto);
        var createResponseDto = createVerificationRequest(createDto);

        var nonce = createResponseDto.requestNonce();
        var requestId = createResponseDto.id().toString();

        // Wallet retrieves Verifier Request
        var state = getStateFromVerificationRequest(requestId, nonce, ResponseModeType.DIRECT_POST_JWT);

        // Check status, should be pending
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));

        // Wallet checks verifier metadata
        assertDoesNotThrow(() -> mvc.perform(get("/oid4vp/api/openid-client-metadata.json")
                        .contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.client_id").value(applicationProperties.getClientIdWithPrefix()))
                .andExpect(jsonPath("$.vp_formats.jwt_vp.alg").value(JWSAlgorithm.ML_DSA_44.getName()))
                .andReturn());
        // Check status, should still be pending
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));

        // Wallet sends valid credential
        var vpToken = Map.of("identity_credential_dcql", List.of(createMockCredential(nonce)));
        var submissionData = objectMapper.writeValueAsString(vpToken);
        assertDoesNotThrow(() -> mvc.perform(post(String.format("%s/%s/response-data", OID4VP_API_BASE_URL, requestId))
                        .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                        .formField("state", "some wrong other state that should be overridden by the correct state in the encrypted data")
                        .formField("response", buildJWTResponse(Map.of("vp_token", submissionData, "state", state), createResponseDto.id())))
                .andExpect(status().isOk()));

        // Status should not have changed, status should not change
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.SUCCESS));
    }

    @ParameterizedTest
    @MethodSource("provideCreateDtosDirectPostJwt")
    void testVerificationFlowDirectPostJWT_walletSendsError(CreateVerificationManagementDto createVerificationManagementDto) throws Exception {
        var createDto = objectMapper.writeValueAsString(createVerificationManagementDto);
        var createResponseDto = createVerificationRequest(createDto);

        var nonce = createResponseDto.requestNonce();
        var requestId = createResponseDto.id().toString();

        // Wallet retrieves Verifier Request
        var state = getStateFromVerificationRequest(requestId, nonce, ResponseModeType.DIRECT_POST_JWT);

        // Check status, should be pending
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));

        // Wallet checks verifier metadata
        assertDoesNotThrow(() -> mvc.perform(get("/oid4vp/api/openid-client-metadata.json")
                        .contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.client_id").value(applicationProperties.getClientIdWithPrefix()))
                .andExpect(jsonPath("$.vp_formats.jwt_vp.alg").value(JWSAlgorithm.ML_DSA_44.getName()))
                .andReturn());
        // Check status, should still be pending
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.PENDING));

        // Wallet sends error response
        assertDoesNotThrow(() -> mvc.perform(post(String.format("%s/%s/response-data", OID4VP_API_BASE_URL, requestId))
                        .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                        .formField("response", buildJWTResponse(Map.of("error", "vp_formats_not_supported","error_description", "I don't want to", "state", state), createResponseDto.id())))
                .andExpect(status().isOk())
        );
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.FAILED));

        // Wallet sends valid credential, should be rejected
        var vpToken = createMockCredential(nonce);
        assertDoesNotThrow(() -> mvc.perform(post(String.format("%s/%s/response-data", OID4VP_API_BASE_URL, requestId))
                        .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                        .formField("response", buildJWTResponse(Map.of("vp_token", vpToken, "state", state), createResponseDto.id())))
                .andExpect(status().isBadRequest()));

        // Status should not have changed, status should not change
        assert (hasStatus(createResponseDto.id().toString(), VerificationStatusDto.FAILED));
    }


    private boolean hasStatus(String requestObjectId, VerificationStatusDto status) {
        MvcResult requestObjectResult = assertDoesNotThrow(() -> (mvc.perform(get(String.format("%s/%s", MANAGEMENT_BASE_URL, requestObjectId))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn()));
        var createResponse = assertDoesNotThrow(() -> objectMapper.readValue(requestObjectResult.getResponse().getContentAsString(), ManagementResponseDto.class));
        return createResponse.state() == status;
    }

    private String getStateFromVerificationRequest(String requestId, String nonce, ResponseModeType expectedResponseMode) throws ParseException, UnsupportedEncodingException, JOSEException {
        MvcResult requestObjectResult = assertDoesNotThrow(() -> (mvc.perform(get(String.format("%s/%s", OID4VP_API_BASE_URL, requestId))
                        .accept("application/oauth-authz-req+jwt"))
                .andExpect(status().isOk())
                .andReturn()));

        var responseJwt = SignedJWT.parse(requestObjectResult.getResponse().getContentAsString());
        // PQEID: ECDSA -> ML-DSA (verifier's own request-object signing key, unrelated to the
        // did_sidekicks Jwk struct limitation - see pqeid-mldsa-did-resolver-blocker)
        assertThat(responseJwt.getHeader().getAlgorithm().getName()).isEqualTo("ML-DSA-44");
        assertThat(responseJwt.getHeader().getKeyID()).isEqualTo(applicationProperties.getSigningKeyVerificationMethod());
        assertThat(responseJwt.verify(new MLDSAVerifier(JWK.parse(PUBLIC_KEY).toMLDSAKey()))).isTrue();

        // checking claims
        var claims = responseJwt.getJWTClaimsSet();
        assertThat(claims.getStringClaim("response_type")).isEqualTo("vp_token");
        assertThat(claims.getStringClaim("response_mode")).isEqualTo(expectedResponseMode.toString());
        assertThat(claims.getStringClaim("nonce")).isEqualTo(nonce);
        assertThat(claims.getStringClaim("response_uri")).isEqualTo(String.format("%s/oid4vp/api/request-object/%s/response-data", applicationProperties.getExternalUrl(), requestId));
        assertThat(claims.getStringClaim("state"))
                .as("The verifier should provide a state").isNotBlank();
        return claims.getStringClaim("state");
    }

    private ManagementResponseDto createVerificationRequest(String body) {
        MvcResult createVerificationResult = assertDoesNotThrow(() -> mvc.perform(post(MANAGEMENT_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn()
        );

        return assertDoesNotThrow(() -> objectMapper.readValue(createVerificationResult.getResponse().getContentAsString(), ManagementResponseDto.class));
    }

    private static CreateVerificationManagementDto createDtoAsContentBodyWithDCQL(ResponseModeTypeDto responseModeTypeDto) {
        return CreateVerificationManagementDto.builder()
                .acceptedIssuerDids(List.of(ACCEPTED_ISSUER))
                .jwtSecuredAuthorizationRequest(true)
                .responseMode(responseModeTypeDto)
                .dcqlQuery(ApiFixtures.getDcqlQueryDto())
                .build();
    }

    private static CreateVerificationManagementDto createNestedDtoAsContentBodyWithDCQL(ResponseModeTypeDto responseModeTypeDto) {
        return CreateVerificationManagementDto.builder()
                .acceptedIssuerDids(List.of(ACCEPTED_ISSUER))
                .jwtSecuredAuthorizationRequest(true)
                .responseMode(responseModeTypeDto)
                .dcqlQuery(ApiFixtures.getDcqlQueryForNestedAddressDto()).build();
    }

    private static Stream<Arguments> provideCreateDtosDirectPost() {
        return Stream.of(
                Arguments.of(createDtoAsContentBodyWithDCQL(ResponseModeTypeDto.DIRECT_POST))
        );
    }

    private static Stream<Arguments> provideCreateNestedDtosDirectPost() {
        return Stream.of(
                Arguments.of(createNestedDtoAsContentBodyWithDCQL(ResponseModeTypeDto.DIRECT_POST))
        );
    }

    private static Stream<Arguments> provideCreateDtosDirectPostJwt() {
        return Stream.of(
                Arguments.of(createDtoAsContentBodyWithDCQL(ResponseModeTypeDto.DIRECT_POST_JWT))
        );
    }

    private String createMockCredential(String nonce) throws NoSuchAlgorithmException, ParseException, JOSEException {
        SDJWTCredentialMock emulator = new SDJWTCredentialMock(ACCEPTED_ISSUER, "some_issuer_id#key-1", KeyFixtures.issuerKey(), KeyFixtures.holderKey());
        mockDidResolverResponse(emulator);

        var sdJWT = emulator.createSDJWTMock();
        return emulator.addKeyBindingProof(sdJWT, nonce, "decentralized_identifier:" + ACCEPTED_ISSUER);
    }

    private String createMockCredential_rec(String nonce) throws NoSuchAlgorithmException, ParseException, JOSEException {
        SDJWTCredentialMock emulator = new SDJWTCredentialMock(ACCEPTED_ISSUER, "some_issuer_id#key-1", KeyFixtures.issuerKey(), KeyFixtures.holderKey());
        mockDidResolverResponse(emulator);

        var sdJWT = emulator.createSDJWTMockWithRecursiveListArray();
        return emulator.addKeyBindingProof(sdJWT, nonce, "decentralized_identifier:" + ACCEPTED_ISSUER);
    }

    private void mockDidResolverResponse(SDJWTCredentialMock sdjwt) {
        try {
            String fragment = "key-1";
            when(didResolverFacade.resolveDid(sdjwt.getIssuerId(), fragment))
                    .thenAnswer(invocation -> DidDocFixtures.issuerDidDocWithJsonWebKey(
                            sdjwt.getIssuerId(),
                            sdjwt.getKidHeaderValue(),
                            KeyFixtures.issuerPublicKeyAsJsonWebKey())
                            .getKey(fragment));
        } catch (DidResolverException | DidSidekicksException e) {
            throw new AssertionError(e);
        }
    }

    private String buildJWTResponse(Map<String,String> fields, UUID requestId) throws ParseException, JOSEException {
        var managementEntity = managementEntityRepository.findById(requestId).orElseThrow();
        var responseSpecification = managementEntity.getResponseSpecification();
        Assertions.assertNotNull(responseSpecification.getJwks());
        // PQEID: ECDH-ES -> XWING, unrelated to the did_sidekicks blocker (locally generated
        // key, never resolved via DID)
        XWingKey publicKey = JWKSet.parse(responseSpecification.getJwks()).getKeys().getFirst().toXWingKey();
        var encryptionMethod = EncryptionMethod.parse(responseSpecification.getEncryptedResponseEncValuesSupported().getFirst());

        var claims = new JWTClaimsSet.Builder();
        fields.forEach(claims::claim);


        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.XWING, encryptionMethod)
                        .keyID(publicKey.getKeyID()).build(),
                claims.build().toPayload()
        );
        jweObject.encrypt(new XWingEncrypter(publicKey));
        return jweObject.serialize();
    }
}