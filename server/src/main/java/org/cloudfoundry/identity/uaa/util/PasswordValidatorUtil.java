package org.cloudfoundry.identity.uaa.util;



import org.cloudfoundry.identity.uaa.authentication.GenericPasswordPolicy;
import org.cloudfoundry.identity.uaa.scim.validate.UaaPasswordPolicyValidator;
import org.passay.*;


import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;


public final class PasswordValidatorUtil {



    public static PropertiesMessageResolver messageResolver(String messagesResourcePath) {
        final Properties props = new Properties();
        InputStream in = null;
        try {
            in = PasswordValidatorUtil.class.getResourceAsStream(
                    messagesResourcePath);
            props.load(in);
            return new PropertiesMessageResolver(props);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Error loading default message properties.",
                    e);
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    public static PasswordValidator validator(GenericPasswordPolicy policy,
                                              MessageResolver messageResolver) {
        List<Rule> rules = new ArrayList<>();

        //length is always a rule. We do not allow blank password
        int minLength = Math.max(1, policy.getMinLength());
        int maxLength = policy.getMaxLength()>0 ? policy.getMaxLength() : Integer.MAX_VALUE;
        rules.add(new LengthRule(minLength, maxLength));
        
        if (policy.getRequireUpperCaseCharacter()>0) {
            CharacterRule characterRule = new CharacterRule(EnglishCharacterData.UpperCase);
            characterRule.setNumberOfCharacters(policy.getRequireUpperCaseCharacter());
            rules.add(characterRule);
        }
        if (policy.getRequireLowerCaseCharacter()>0) {
            CharacterRule characterRule = new CharacterRule(EnglishCharacterData.LowerCase);
            characterRule.setNumberOfCharacters(policy.getRequireLowerCaseCharacter());
            rules.add(characterRule);
        }
        if (policy.getRequireDigit()>0) {
            CharacterRule characterRule = new CharacterRule(EnglishCharacterData.Digit);
            characterRule.setNumberOfCharacters(policy.getRequireDigit());
            rules.add(characterRule);
        }
        if (policy.getRequireSpecialCharacter() > 0) {
            CharacterRule characterRule = new CharacterRule(EnglishCharacterData.Special);
            characterRule.setNumberOfCharacters(policy.getRequireSpecialCharacter());
            rules.add(characterRule);
        }
        return new PasswordValidator(messageResolver, rules);
    }
}
