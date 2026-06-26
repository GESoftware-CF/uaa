package org.cloudfoundry.identity.uaa.zone;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.client.ClientAdminEndpointsValidator;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm;
import org.cloudfoundry.identity.uaa.zone.model.ConnectionDetails;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneHeader;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasLength;
import static org.springframework.util.StringUtils.hasText;

public class OrchestratorZoneService implements ApplicationEventPublisherAware {

    public static final String X_IDENTITY_ZONE_ID = "X-Identity-Zone-Id";
    public static final String GENERATED_KEY_ID = "generated-saml-key";
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public static final String LOGOUT_REDIRECT_URL_WHITELIST_KEY = "logout_redirect_url_whitelist";

    public static final String CLIENT_ID = "admin";
    public static final String ZONE_AUTHORITIES =
        "uaa.admin,clients.admin,clients.read,clients.write,clients.secret,idps.read,idps.write,sps" +
        ".read,sps.write,scim.read,scim.write,uaa.resource";
    public static final String GRANT_TYPES = "client_credentials";
    public static final String RESOURCE_IDS = "none";
    public static final String SCOPES = "uaa.none";
    public static final String ZONE_CREATED_MESSAGE = "Zone Created Successfully";
    public static final String ZONE_DELETED_MESSAGE = "Zone Deleted Successfully";

    private static final java.util.Base64.Encoder base64encoder = java.util.Base64.getMimeEncoder(64, "\n".getBytes());
    public static final String DASHBOARD_LOGIN_PATH = "/#/login/";

    private final IdentityZoneProvisioning zoneProvisioning;
    private final IdentityProviderProvisioning idpProvisioning;
    private final ScimGroupProvisioning groupProvisioning;
    private final QueryableResourceManager<ClientDetails> clientDetailsService;
    private final ClientAdminEndpointsValidator clientDetailsValidator;
    private final String uaaDashboardUri;
    private final String uaaUrl;
    private final String issuerUri;

    private ApplicationEventPublisher publisher;

    private static final Logger logger = LoggerFactory.getLogger(OrchestratorZoneService.class);

    public OrchestratorZoneService(IdentityZoneProvisioning zoneProvisioning,
                                   IdentityProviderProvisioning idpProvisioning,
                                   ScimGroupProvisioning groupProvisioning,
                                   QueryableResourceManager<ClientDetails> clientDetailsService,
                                   ClientAdminEndpointsValidator clientDetailsValidator,
                                   String uaaDashboardUri, String uaaUrl,
                                   String issuerUri
                                  ) {
        this.zoneProvisioning = zoneProvisioning;
        this.idpProvisioning = idpProvisioning;
        this.groupProvisioning = groupProvisioning;
        this.clientDetailsService = clientDetailsService;
        this.clientDetailsValidator = clientDetailsValidator;
        this.uaaDashboardUri = uaaDashboardUri;
        this.uaaUrl = uaaUrl;
        this.issuerUri = issuerUri;
    }

    public OrchestratorZoneResponse getZoneDetails(String zoneName) {
        OrchestratorZoneEntity orchestratorZone = zoneProvisioning.retrieveByName(zoneName);
        ConnectionDetails connectionDetails = buildConnectionDetails(orchestratorZone);
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setName(zoneName);
        response.setConnectionDetails(connectionDetails);
        response.setMessage("");
        response.setState(OrchestratorState.FOUND.toString());
        return response;
    }

    public OrchestratorZoneResponse deleteZone(String zoneName) {
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            logger.debug("Zone - deleting Name[" + zoneName + "]");
            OrchestratorZoneEntity orchestratorZone = zoneProvisioning.retrieveByName(zoneName);
            IdentityZone zone = zoneProvisioning.retrieve(orchestratorZone.getIdentityZoneId());
            IdentityZoneHolder.set(zone);
            if (publisher != null && zone != null) {
                zoneProvisioning.deleteOrchestratorZone(zoneName);
                publisher.publishEvent(
                    new EntityDeletedEvent<>(zone, SecurityContextHolder.getContext().getAuthentication(),
                                             IdentityZoneHolder.getCurrentZoneId()));
                logger.debug("Zone - deleted id[" + zone.getId() + "]");
            } else {
                throw new OrchestratorZoneServiceException(zoneName, "Error : deleting zone Name[" + zoneName + "]");
            }
        } finally {
            IdentityZoneHolder.set(previous);
        }

        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setName(zoneName);
        response.setMessage(ZONE_DELETED_MESSAGE);
        response.setState(OrchestratorState.DELETE_IN_PROGRESS.toString());
        return response;
    }

    private ConnectionDetails buildConnectionDetails(OrchestratorZoneEntity orchestratorZone) {
        ConnectionDetails connectionDetails = new ConnectionDetails();
        connectionDetails.setUri(constructUri(orchestratorZone.getSubdomain(), uaaUrl, ""));
        connectionDetails.setIssuerId(constructUri(orchestratorZone.getSubdomain(), issuerUri, "oauth/token"));
        connectionDetails.setSubdomain(orchestratorZone.getSubdomain());
        connectionDetails.setDashboardUri(uaaDashboardUri + DASHBOARD_LOGIN_PATH + orchestratorZone.getIdentityZoneId());
        OrchestratorZoneHeader zoneHeader = new OrchestratorZoneHeader(X_IDENTITY_ZONE_ID, orchestratorZone.getIdentityZoneId());
        connectionDetails.setZone(zoneHeader);
        return connectionDetails;
    }

    private String constructUri(String subDomain, String baseUrl, String path) {
        URI uri = URI.create(baseUrl);
        String hostToUse = uri.getHost();
        if (hasText(subDomain)) {
            hostToUse = subDomain + "." + hostToUse;
        }
        return UriComponentsBuilder.fromUri(uri).host(hostToUse).pathSegment(path).build().toUriString();
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public OrchestratorZoneResponse createZone(OrchestratorZoneRequest zoneRequest) {
        if (!IdentityZoneHolder.isUaa()) {
            throw new AccessDeniedException("Zones can only be created by being authenticated in the default zone.");
        }

        // Validate additional parameters before processing
        if (zoneRequest.getParameters() != null && zoneRequest.getParameters().getAdditionalParameters() != null) {
            validateAdditionalParameters(zoneRequest.getParameters().getAdditionalParameters());
        }

        String orchestratorZoneName = zoneRequest.getName();
        String identityZoneName = orchestratorZoneName; // Default to zone request name

        // Extract tenant_alias for identity zone display name if present
        if (zoneRequest.getParameters() != null &&
            zoneRequest.getParameters().getAdditionalParameters() != null) {
            Object tenantAliasObj = zoneRequest.getParameters().getAdditionalParameters().get("tenant_alias");
            if (tenantAliasObj instanceof String) {
                String tenantAlias = (String) tenantAliasObj;
                if (tenantAlias != null && !tenantAlias.trim().isEmpty()) {
                    identityZoneName = tenantAlias;
                }
            }
        }

        String importedServiceInstanceGuid = zoneRequest.getParameters().getImportedServiceInstanceGuid();
        if (Objects.nonNull(importedServiceInstanceGuid)) {
            return importZone(zoneRequest);
        }
        String adminClientSecret = zoneRequest.getParameters().getAdminClientSecret();
        String subdomain = zoneRequest.getParameters().getSubdomain();
        String id = UUID.randomUUID().toString();
        subdomain = getSubDomain(subdomain, id);
        IdentityZone identityZone = generateIdentityZone(subdomain, identityZoneName, id, zoneRequest.getParameters());
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            IdentityZone created = createIdentityZone(identityZone);
            // This DAO method will throw ConstraintViolationException
            // if there is a duplicate entry in orchestrator_zone table
            // Orchestrator zone name is always the name from zoneRequest
            zoneProvisioning.createOrchestratorZone(identityZone.getId(), orchestratorZoneName);
            IdentityZoneHolder.set(created);
            createDefaultIdp(created);
            createUserGroups(created);
            createZoneAdminClient(adminClientSecret, created);
        } finally {
            IdentityZoneHolder.set(previous);
        }
        return getOrchestratorZoneResponse(zoneRequest);
    }

    private static OrchestratorZoneResponse getOrchestratorZoneResponse(OrchestratorZoneRequest zoneRequest) {
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setName(zoneRequest.getName());
        response.setMessage(ZONE_CREATED_MESSAGE);
        response.setState(OrchestratorState.CREATE_IN_PROGRESS.toString());
        return response;
    }

    private OrchestratorZoneResponse importZone(OrchestratorZoneRequest zoneRequest) {
        String importedServiceInstanceGuid = zoneRequest.getParameters().getImportedServiceInstanceGuid();
        logger.info("Importing existing Identity Zone {}", importedServiceInstanceGuid);
        // Retrieve native and orchestrator zone using LEFT JOIN,
        // Case1: If response contains no record, native zone not available or invalid importServiceInstanceGuid
        // Case2: If response contains native zone alone, zone can be imported
        // Case3: If response contains both native and orchestrator, zone already imported.
        OrchestratorZoneEntity orchestratorZone = zoneProvisioning.retrieveOrchestratorZoneByIdentityZoneId(importedServiceInstanceGuid);
        if (!isZoneNotFoundOrAlreadyImported(orchestratorZone)) {
            zoneProvisioning.createOrchestratorZone(orchestratorZone.getIdentityZoneId(), zoneRequest.getName());
        }
        return getOrchestratorZoneResponse(zoneRequest);
    }

    private boolean isZoneNotFoundOrAlreadyImported(OrchestratorZoneEntity orchestratorZone) {

        if (Objects.nonNull(orchestratorZone.getOrchestratorZoneName())) {
            String errorMessage = String.format("Unable to create orchestrator import claim. UAA Zone" +
                    " already imported with name %s", orchestratorZone.getOrchestratorZoneName());
            logger.error(errorMessage);
            throw new ZoneAlreadyExistsException(errorMessage);
        }
        return false;
    }

    private String getSubDomain(String subdomain, String id) {
        if (subdomain == null) {
            subdomain = id;
        }
        return subdomain;
    }

    private void createZoneAdminClient(String adminClientSecret, IdentityZone created) {
        String zoneId = IdentityZoneHolder.get().getId();
        String authorities = ZONE_AUTHORITIES + ",zones." + zoneId + ".admin";
        try {
            createZoneAdminClient(created.getId(), authorities, CLIENT_ID, adminClientSecret, GRANT_TYPES, RESOURCE_IDS,
                                  SCOPES);
        } catch (Exception e) {
            String errorMessage = String.format("Unable to create client for zone name : %s  failed.", created.getName());
            logger.error(errorMessage, e);
            throw new OrchestratorZoneServiceException(created.getName(), errorMessage+" Exception is :" + e.getMessage());
        }
    }

    private void createDefaultIdp(IdentityZone created) {
        try {
            IdentityProvider defaultIdp = new IdentityProvider();
            defaultIdp.setName(OriginKeys.UAA);
            defaultIdp.setType(OriginKeys.UAA);
            defaultIdp.setOriginKey(OriginKeys.UAA);
            defaultIdp.setIdentityZoneId(created.getId());
            UaaIdentityProviderDefinition idpDefinition = new UaaIdentityProviderDefinition();
            idpDefinition.setPasswordPolicy(null);
            defaultIdp.setConfig(idpDefinition);
            idpProvisioning.create(defaultIdp, created.getId());
            logger.debug("Created default IDP in zone - created zone name [" + created.getName() + "]");
        } catch (Exception e) {
            String errorMessage = String.format(
                "Unable to create identity provider for zone name : %s",
                created.getName());
            logger.error(errorMessage, e);
            throw new OrchestratorZoneServiceException(created.getName(), errorMessage + " Exception is : " + e.getMessage());
        }
    }

    private IdentityZone createIdentityZone(IdentityZone identityZone) {
        IdentityZone created = null;
        try {
            logger.debug("Zone - creating zone name [" + identityZone.getName() + "]");
            created = zoneProvisioning.create(identityZone);
            logger.debug("Zone - created zone name [" + identityZone.getName() + "]");
        } catch (ZoneAlreadyExistsException e) {
            String errorMessage = String.format("The subdomain name %s is already taken. Please use a different subdomain",
                                                identityZone.getSubdomain());
            logger.error(errorMessage, e);
            throw new ZoneAlreadyExistsException(identityZone.getName(), errorMessage, e);
        } catch (Exception e) {
            String errorMessage = String.format("Unexpected exception while creating identity zone for zone name : " +
                                                "%s", identityZone.getName());
            logger.error(errorMessage, e);
            throw new OrchestratorZoneServiceException(identityZone.getName(), errorMessage);
        }
        return created;
    }

    protected IdentityZone generateIdentityZone(String subdomain, String name, String id, OrchestratorZone orchestratorZone) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setName(name);
        identityZone.setSubdomain(subdomain);
        setTokenPolicy(createSigningKey(name), identityZone);
        setSamlConfig(identityZone);
        identityZone.getConfig().getLinks().getLogout().setWhitelist(createDeploymentSpecificLogoutWhiteList(orchestratorZone));
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(false);
        identityZone.getConfig().getLinks().getSelfService().setSignup("");
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceResetPasswordEnabled(true);
        return identityZone;
    }

    private void setSamlConfig(IdentityZone identityZone) {
        try {
            identityZone.getConfig().setSamlConfig(createSamlConfig(identityZone.getSubdomain()));
        } catch (Exception e) {
            String errorMessage = String.format(
                "Unexpected exception while create saml config for zone name: %s",
                identityZone.getName());
            logger.error(errorMessage, e);
            throw new OrchestratorZoneServiceException(identityZone.getName(), errorMessage+ " Exception is : " + e.getMessage());
        }
    }

    private void setTokenPolicy(String zoneSigningKey, IdentityZone identityZone) {
        String activeKeyId = new RandomValueStringGenerator(5).generate();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setActiveKeyId(activeKeyId);
        tokenPolicy.setKeys(Collections.singletonMap(activeKeyId, zoneSigningKey));
        identityZone.getConfig().setTokenPolicy(tokenPolicy);
    }

    private String createSigningKey(String zoneName) {
        StringWriter pemStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(pemStringWriter);
        try {
            KeyPairGenerator keyPairGenerator = null;
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            pemWriter.writeObject(keyPairGenerator.genKeyPair().getPrivate());
        } catch (Exception e) {
            logAndThrowException(zoneName, e);
        } finally {
            try {
                pemWriter.flush();
                pemWriter.close();
            } catch (IOException e) {
                logAndThrowException(zoneName, e);
            }
        }
        return pemStringWriter.toString();
    }

    private void logAndThrowException(String zoneName, Exception e) {
        String errorMessage = String.format(
            "Unexpected exception while create signingKey for zone name : %s",
            zoneName);
        logger.error(errorMessage, e);
        throw new OrchestratorZoneServiceException(zoneName, errorMessage + " Exception is : " + e.getMessage());
    }

    private void createZoneAdminClient(final String id, final String authorities, final String clientId,
                                       final String clientSecret,
                                       final String grantTypes, final String resourceIds, final String scopes) {
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, resourceIds, scopes, grantTypes, authorities);
        clientDetails.setClientSecret(clientSecret);
        ClientDetails details = clientDetailsValidator.validate(clientDetails, true, false);
        clientDetailsService.create(details, id);
    }

    private void createUserGroups(IdentityZone zone) {
        UserConfig userConfig = zone.getConfig().getUserConfig();
        if (userConfig != null) {
            List<String> defaultGroups = ofNullable(userConfig.getDefaultGroups()).orElse(Collections.emptyList());
            logger.debug(String.format("About to create default groups count: %s for zone name: %s",
                    defaultGroups.size(), zone.getName()));
            for (String group : defaultGroups) {
                logger.debug(String.format("Creating zone default group: %s for zone name: %s", group,
                        zone.getName()));
                groupProvisioning.createOrGet(
                        new ScimGroup(
                                null,
                                group,
                                zone.getId()
                        ),
                        zone.getId()
                );
            }
        }
    }

    private List<String> createDeploymentSpecificLogoutWhiteList(OrchestratorZone orchestratorZone) {
        List<String> whiteList = new java.util.ArrayList<>();

        // Add redirect URLs from additionalParameters if present
        if (orchestratorZone != null && orchestratorZone.getAdditionalParameters() != null) {
            List<String> redirectUrls = extractRedirectUrls(orchestratorZone.getAdditionalParameters());
            if (!redirectUrls.isEmpty()) {
                whiteList.addAll(redirectUrls);
            }
        }

        // Add deployment-specific logout whitelist
        String runDomainFQDN = getRunDomainFromUAADomain();
        if (!hasLength(runDomainFQDN)) {
            whiteList.add("http*://**");
        } else {
            whiteList.add("http*://**" + runDomainFQDN);
        }

        return whiteList;
    }

    /**
     * Validates the additional parameters map.
     * Rules:
     * 1. Maximum of 2 keys are allowed
     * 2. Only "logout_redirect_url_whitelist" and "tenant_alias" keys are allowed
     * 3. "logout_redirect_url_whitelist" must be a List of Strings (single strings not allowed)
     * 4. "tenant_alias" must be a String
     *
     * @param additionalParameters Map containing additional parameters
     * @throws OrchestratorZoneServiceException if validation fails
     */
    private void validateAdditionalParameters(java.util.Map<String, Object> additionalParameters) {
        if (additionalParameters == null || additionalParameters.isEmpty()) {
            return;
        }

        // Validate maximum number of keys
        if (additionalParameters.size() > 2) {
            throw new OrchestratorZoneServiceException(
                    "Additional parameters can contain maximum 2 keys. Found " + additionalParameters.size() + " keys.");
        }

        // Define allowed keys
        java.util.Set<String> allowedKeys = new java.util.HashSet<>();
        allowedKeys.add(LOGOUT_REDIRECT_URL_WHITELIST_KEY);
        allowedKeys.add("tenant_alias");

        // Validate that only allowed keys are present
        for (String key : additionalParameters.keySet()) {
            if (!allowedKeys.contains(key)) {
                throw new OrchestratorZoneServiceException(
                        "Invalid key '" + key + "' in additional parameters. Only 'logout_redirect_url_whitelist' and 'tenant_alias' are allowed.");
            }
        }

        // Validate logout_redirect_url_whitelist if present
        if (additionalParameters.containsKey(LOGOUT_REDIRECT_URL_WHITELIST_KEY)) {
            Object redirectUrlValue = additionalParameters.get(LOGOUT_REDIRECT_URL_WHITELIST_KEY);

            if (redirectUrlValue == null) {
                // null is acceptable, skip validation
            } else if (redirectUrlValue instanceof List) {
                // Validate that all elements in the list are Strings
                List<?> urlList = (List<?>) redirectUrlValue;
                for (int i = 0; i < urlList.size(); i++) {
                    Object element = urlList.get(i);
                    if (!(element instanceof String)) {
                        throw new OrchestratorZoneServiceException(
                                "logout_redirect_url_whitelist must be an array of Strings. " +
                                "Element at index " + i + " is of type: " +
                                (element != null ? element.getClass().getSimpleName() : "null"));
                    }
                }
            } else {
                throw new OrchestratorZoneServiceException(
                        "logout_redirect_url_whitelist must be an array of Strings. Found type: " +
                        redirectUrlValue.getClass().getSimpleName());
            }
        }

        // Validate tenant_alias if present
        if (additionalParameters.containsKey("tenant_alias")) {
            Object tenantAliasValue = additionalParameters.get("tenant_alias");

            if (tenantAliasValue != null && !(tenantAliasValue instanceof String)) {
                throw new OrchestratorZoneServiceException(
                        "tenant_alias must be a String. Found type: " +
                        tenantAliasValue.getClass().getSimpleName());
            }
        }
    }

    /**
     * Extracts redirect URLs from the additionalParameters map.
     * The logout_redirect_url_whitelist key must contain a list of URL strings.
     * Empty or blank strings are filtered out.
     *
     * @param additionalParameters Map containing additional parameters
     * @return List of redirect URLs, or empty list if none found
     */
    private List<String> extractRedirectUrls(java.util.Map<String, Object> additionalParameters) {
        if (additionalParameters == null || additionalParameters.isEmpty()) {
            return Collections.emptyList();
        }

        Object redirectUrlValue = additionalParameters.get(LOGOUT_REDIRECT_URL_WHITELIST_KEY);

        if (redirectUrlValue == null) {
            return Collections.emptyList();
        }

        if (redirectUrlValue instanceof List) {
            return ((List<?>) redirectUrlValue).stream()
                    .filter(obj -> obj instanceof String)
                    .map(obj -> (String) obj)
                    .filter(url -> hasText(url))
                    .collect(java.util.stream.Collectors.toList());
        }

        return Collections.emptyList();
    }

    /**
     * Remove all characters till first dot
     */
    private String getRunDomainFromUAADomain() {
        if (!hasLength(uaaUrl))  return uaaUrl;
        int firstDotIndex = uaaUrl.indexOf('.');
        if (firstDotIndex == -1)  return "";
        return uaaUrl.substring(firstDotIndex);
    }

    private SamlConfig createSamlConfig(String subdomain)
        throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        StringWriter pemStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(pemStringWriter);
        SamlConfig samlConfig = new SamlConfig();
        try {
            JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder("DES-EDE3-CBC");
            builder.setProvider("BCFIPS");
            String passphrase = new RandomValueStringGenerator(8).generate();
            PEMEncryptor pemEncryptor = builder.build(passphrase.toCharArray());
            KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
            rsa.initialize(2048);
            KeyPair kp = rsa.generateKeyPair();

            JcaMiscPEMGenerator pemGenerator = new JcaMiscPEMGenerator(kp.getPrivate(), pemEncryptor);
            pemWriter.writeObject(pemGenerator);
            pemWriter.flush();

            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.YEAR, 10);

            byte[] pk = kp.getPublic().getEncoded();
            SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(pk);
            String dn = "C=US, ST=CA, L=San Ramon, O=GE, OU=GE Digital, CN=PredixUAA"+subdomain;
            X509v1CertificateBuilder certGen = new X509v1CertificateBuilder(
                new X500Name(dn),
                BigInteger.ONE,
                new Date(),
                cal.getTime(),
                new X500Name(dn),
                bcPk
            );
            X509CertificateHolder certHolder = certGen
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));

            HashMap<String, SamlKey> samlKeys = new HashMap<>();

            String certificate = BEGIN_CERT + "\n" + base64encoder.encodeToString(certHolder.getEncoded()) + "\n" + END_CERT;

            samlKeys.put(GENERATED_KEY_ID, new SamlKey(pemStringWriter.toString(), passphrase, certificate));
            samlConfig.setKeys(samlKeys);
            samlConfig.setActiveKeyId(GENERATED_KEY_ID);
        } finally {
            pemWriter.flush();
            pemWriter.close();
        }
        return samlConfig;
    }
}
