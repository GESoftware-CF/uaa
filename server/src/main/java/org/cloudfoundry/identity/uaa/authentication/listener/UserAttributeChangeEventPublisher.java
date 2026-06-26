package org.cloudfoundry.identity.uaa.authentication.listener;

import com.ge.iam.sns.service.MessageBuilder;
import com.ge.iam.sns.service.SnsService;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Collections;

/**
 * Publishes user attribute change events to SNS.
 * This class is conditionally created when sns.enabled=true.
 */
@Component
@ConditionalOnProperty(name = "sns.enabled", havingValue = "true", matchIfMissing = false)
public class UserAttributeChangeEventPublisher {

    private static final Logger logger = LoggerFactory.getLogger(UserAttributeChangeEventPublisher.class);

    private final SnsService snsService;
    private final String snsTopicArn;
    private final boolean filterUaaOrigin;

    @Autowired
    public UserAttributeChangeEventPublisher(SnsService snsService,
            @Value("${sns.topic.arn:}") String snsTopicArn,
            @Value("${sns.filter.origin.uaa:false}") boolean filterUaaOrigin) {
        this.snsService = snsService;
        this.snsTopicArn = snsTopicArn;
        this.filterUaaOrigin = filterUaaOrigin;
    }

    public void publishUserAttributeChangeEventAsync(UaaUser user) {
        // Filter out UAA origin users if configured
        if (filterUaaOrigin && OriginKeys.UAA.equals(user.getOrigin())) {
            logger.debug("SNS publishing skipped - user is from password-based (UAA) origin. Username: {}",
                    user.getUsername());
            return;
        }

        // Use previousUser from the user object if available (set by SAML flow when
        // attributes changed)
        // If not available, we'll still publish login events (lastLogonTime changes)
        UaaUser userBefore = user.getPreviousUser() != null ? user.getPreviousUser() : user;

        Map<String, Object> context = createContext(userBefore, user);
        MessageBuilder userEventMessageBuilder = this::buildUserEventMessage;

        try {
            snsService.publishAsync(snsTopicArn, "UAA User Update Event", userEventMessageBuilder, context)
                    .whenComplete((result, throwable) -> {
                        if (throwable != null) {
                            logger.error("Failed to publish user event to SNS. " +
                                    "This failure will not affect application functionality.", throwable);
                        } else {
                            logger.info("User event published to SNS successfully");
                        }
                    });
        } catch (Exception e) {
            logger.error("Failed to initiate SNS publish", e);
        }
    }

    private Map<String, Object> createContext(UaaUser existingUser, UaaUser updatedUser) {
        Map<String, Object> context = new HashMap<>();
        context.put("existingUser", existingUser);
        context.put("updatedUser", updatedUser);
        return Collections.unmodifiableMap(context);
    }

    private JsonObject buildUserEventMessage(Object ctx) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> eventContext = (Map<String, Object>) ctx;

            UaaUser existingUser = (UaaUser) eventContext.get("existingUser");
            UaaUser updatedUser = (UaaUser) eventContext.get("updatedUser");

            if (existingUser == null || updatedUser == null) {
                logger.warn("Skipping SNS publish - null user provided: existing={}, updated={}",
                        existingUser != null, updatedUser != null);
                return null;
            }

            Map<String, Object> changedFields = getChangedFields(existingUser, updatedUser);

            // Always publish login events - even if changedFields is empty, it means a
            // login occurred
            // Empty changedFields happens when previousUser is not set (same object
            // compared to itself)
            if (changedFields.isEmpty()) {
                logger.debug("No attribute changes detected, but publishing login event with current lastLogonTime");
                // Create a minimal change map with just the login event
                changedFields = new HashMap<>();
                changedFields.put("lastLogonTime", updatedUser.getLastLogonTime());
            }

            logger.debug("Processing user attribute change event: {} field(s) changed", changedFields.keySet());

            Map<String, Object> messageMap = createUserEventMessage(updatedUser, changedFields);
            return convertToJsonObject(messageMap);

        } catch (Exception e) {
            logger.error("Error building message for user event", e);
            return null;
        }
    }

    private JsonObject convertToJsonObject(Map<String, Object> messageMap) {
        JsonObject jsonMessage = new JsonObject();
        messageMap.forEach((key, value) -> addPropertyToJson(jsonMessage, key, value));
        return jsonMessage;
    }

    private void addPropertyToJson(JsonObject jsonObject, String key, Object value) {
        if (value instanceof String) {
            jsonObject.addProperty(key, (String) value);
        } else if (value instanceof Number) {
            jsonObject.addProperty(key, (Number) value);
        } else if (value instanceof Boolean) {
            jsonObject.addProperty(key, (Boolean) value);
        } else if (value instanceof Map) {
            jsonObject.add(key, convertMapToJsonObject((Map<?, ?>) value));
        } else if (value != null) {
            jsonObject.addProperty(key, value.toString());
        }
    }

    private JsonObject convertMapToJsonObject(Map<?, ?> map) {
        Gson gson = new Gson();
        return gson.toJsonTree(map).getAsJsonObject();
    }

    private Map<String, Object> getChangedFields(UaaUser existingUser, UaaUser user) {
        Map<String, Object> changedFields = new HashMap<>();

        if (isFirstTimeLogin(existingUser)) {
            return getFirstTimeLoginFields(user);
        }

        addIfChanged(changedFields, "email", existingUser.getEmail(), user.getEmail());
        addNameChangesIfNotSwapped(changedFields, existingUser, user);
        addIfChanged(changedFields, "phoneNumber", existingUser.getPhoneNumber(), user.getPhoneNumber());
        addIfChanged(changedFields, "username", existingUser.getUsername(), user.getUsername());

        if (!java.util.Objects.equals(existingUser.getLastLogonTime(), user.getLastLogonTime())) {
            changedFields.put("lastLogonTime", user.getLastLogonTime());
        }

        return changedFields;
    }

    private boolean isFirstTimeLogin(UaaUser existingUser) {
        return existingUser.getLastLogonTime() == null;
    }

    private Map<String, Object> getFirstTimeLoginFields(UaaUser user) {
        Map<String, Object> fields = new HashMap<>();

        addIfNotNull(fields, "email", user.getEmail());
        addIfNotNull(fields, "givenName", user.getGivenName());
        addIfNotNull(fields, "familyName", user.getFamilyName());
        addIfNotNull(fields, "phoneNumber", user.getPhoneNumber());
        fields.put("lastLogonTime", user.getLastLogonTime());

        return fields;
    }

    private void addIfNotNull(Map<String, Object> fields, String key, Object value) {
        if (value != null) {
            fields.put(key, value);
        }
    }

    private void addIfChanged(Map<String, Object> fields, String key, String oldValue, String newValue) {
        if (!StringUtils.equals(oldValue, newValue)) {
            fields.put(key, newValue);
        }
    }

    private void addNameChangesIfNotSwapped(Map<String, Object> changedFields, UaaUser existingUser, UaaUser user) {
        boolean givenNameChanged = !StringUtils.equals(existingUser.getGivenName(), user.getGivenName());
        boolean familyNameChanged = !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName());

        boolean isNameSwap = StringUtils.equals(existingUser.getGivenName(), user.getFamilyName()) &&
                StringUtils.equals(existingUser.getFamilyName(), user.getGivenName());

        if (givenNameChanged && !isNameSwap) {
            changedFields.put("givenName", user.getGivenName());
        }

        if (familyNameChanged && !isNameSwap) {
            changedFields.put("familyName", user.getFamilyName());
        }
    }

    private Map<String, Object> createUserEventMessage(UaaUser user, Map<String, Object> changedFields) {
        Map<String, Object> message = new HashMap<>();

        String eventType = determineEventType(changedFields);
        message.put("eventType", eventType);
        message.put("source", user.getUsername());
        message.put("version", "updated");
        message.put("username", user.getUsername());
        message.put("instanceZoneId", user.getZoneId());
        message.put("changedFields", changedFields);

        return message;
    }

    private String determineEventType(Map<String, Object> changedFields) {
        if (changedFields.size() == 1 && changedFields.containsKey("lastLogonTime")) {
            return "LOGIN_TIME_UPDATED";
        }
        return "USER_DATA_UPDATED";
    }
}
