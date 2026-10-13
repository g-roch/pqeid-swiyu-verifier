package ch.admin.bj.swiyu.verifier.dto.metadata;

import java.util.HashSet;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ValidJwtValuesValidator implements ConstraintValidator<ValidJwtValues, List<String>> {
    @Override
    public boolean isValid(List<String> jwtAlgorithms, ConstraintValidatorContext constraintValidatorContext) {

        if (jwtAlgorithms == null || jwtAlgorithms.isEmpty()) {
            return false;
        }

        // PQEID: currently UNUSED (its only user, OpenIdClientMetadataVpFormat, is referenced nowhere
        var validAlgsList = List.of(JWSAlgorithm.ML_DSA_44);

        var validAlgorithms = new HashSet<>(validAlgsList.stream().map(JWSAlgorithm::getName).toList());

        return validAlgorithms.containsAll(jwtAlgorithms) && validAlgorithms.size() == new HashSet<>(jwtAlgorithms).size();
    }
}