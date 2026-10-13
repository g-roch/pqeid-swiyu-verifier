package ch.admin.bj.swiyu.verifier.common.config;


import com.nimbusds.jose.JWSAlgorithm;

import java.util.Set;
import java.util.stream.Collectors;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
@Data
@ConfigurationProperties(prefix = "application")
public class ApplicationProperties {

    @NotNull
    private Integer verificationTTL;

    @NotNull
    private String externalUrl;

    @NotNull
    private String clientId;

    @Nullable
    private String clientIdPrefix;

    @NotEmpty
    private String deeplinkSchema;

    @NotNull
    private String signingKey;

    @NotNull
    private String signingKeyVerificationMethod;

    @NotNull
    private String keyManagementMethod;

    // Temporary change: do not alter this value here (default is 100000).
    // Limits the maximum length of compressed ciphertext accepted by the application
    // to avoid excessive memory usage or potential DoS.
    @NotNull
    private Integer maxCompressedCipherTextLength;

    @NotNull
    private Integer maxVcsAccepted = 1;

    private HSMProperties hsm;

    private List<String> acceptedRegistryHosts;

    // PQEID: unencrypted presentations (response_mode=direct_post) are refused unless explicitly allowed
    private boolean allowUnencryptedPresentations = false;

    // PQEID: accepted JWS signature algorithms (policy). Expand phase: ML-DSA-44 +
    // composite. Contract phase = remove ML-DSA-44 here (configuration only).
    @NotEmpty
    private List<String> acceptedSignatureAlgorithms = List.of("ML-DSA-44", "ML-DSA-65-ES256");

    /** The policy as nimbus algorithms (not a JavaBean getter, so Spring doesn't try to bind it). */
    public Set<JWSAlgorithm> acceptedSignatureJwsAlgorithms() {
        return acceptedSignatureAlgorithms.stream()
                .map(JWSAlgorithm::parse)
                .collect(Collectors.toUnmodifiableSet());
    }

    public String getClientIdWithPrefix() {
        return getClientIdWithPrefix(clientId);
    }

    public String getClientIdWithPrefix(String clientId) {
        if (StringUtils.isBlank(clientIdPrefix)) {
            return clientId;
        }

        return clientIdPrefix + ":" + clientId;
    }

}