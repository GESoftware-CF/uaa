package org.cloudfoundry.identity.uaa.zone;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Pattern;

import static java.util.Optional.ofNullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.cloudfoundry.identity.uaa.zone.model.ConnectionDetails;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneHeader;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;

import org.springframework.util.StringUtils;

public class OrchestratorZoneService {

    private static final Logger logger = LoggerFactory.getLogger(OrchestratorZoneService.class);

    public static final String X_IDENTITY_ZONE_ID = "X-Identity-Zone-Id";
    public static final String GENERATED_KEY_ID = "generated-saml-key";
    private static final String SUBDOMAIN_REGEX = "(?:[A-Za-z0-9][A-Za-z0-9\\-]{0,61}[A-Za-z0-9]|[A-Za-z0-9])";
    private static final Pattern SUBDOMAIN_PATTERN;
    public static final String UAA_CUSTOM_SUBDOMAIN = "subdomain";
    public static final String UAA_ADMIN_SECRET = "adminSecret";
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    private static final java.util.Base64.Encoder base64encoder = java.util.Base64.getMimeEncoder(64, "\n".getBytes());
    private final IdentityZoneProvisioning zoneProvisioning;
    private final IdentityProviderProvisioning idpProvisioning;
    private final ScimGroupProvisioning groupProvisioning;
    private final QueryableResourceManager<ClientDetails> clientDetailsService;
    private final ClientDetailsValidator clientDetailsValidator;
    private final String uaaDashboardUri;
    private final String clientId;
    private final String zoneAuthorities;
    private final String grantTypes;
    private final String resourceIds;
    private final String scopes;
    private final String uaaClientID;
    private final String domainName;

    static {
        SUBDOMAIN_PATTERN = Pattern.compile(SUBDOMAIN_REGEX);
    }

    public OrchestratorZoneService(IdentityZoneProvisioning zoneProvisioning,
                       IdentityProviderProvisioning idpProvisioning,
                       ScimGroupProvisioning groupProvisioning,
                       QueryableResourceManager<ClientDetails> clientDetailsService,
                       ClientDetailsValidator clientDetailsValidator,
                       String uaaDashboardUri, String clientId, String zoneAuthorities, String grantTypes,
                       String resourceIds, String scopes, String uaaClientID, String uaaUrl
                      ) {
        this.zoneProvisioning = zoneProvisioning;
        this.idpProvisioning = idpProvisioning;
        this.groupProvisioning = groupProvisioning;
        this.clientDetailsService = clientDetailsService;
        this.clientDetailsValidator = clientDetailsValidator;
        this.uaaDashboardUri = uaaDashboardUri;
        this.clientId = clientId;
        this.zoneAuthorities = zoneAuthorities;
        this.grantTypes = grantTypes;
        this.resourceIds = resourceIds;
        this.scopes = scopes;
        this.uaaClientID = uaaClientID;
        this.domainName = uaaUrl;
    }

    public OrchestratorZoneResponse getOrchestratorZoneDetails(String zoneName) {
        IdentityZone identityZone = zoneProvisioning.retrieveByName(zoneName);
        OrchestratorZone zone = new OrchestratorZone(null, getSubDomainStr(identityZone));
        String uaaUri = ServletUriComponentsBuilder.fromCurrentContextPath().toUriString();
        String subDomain = identityZone.getSubdomain();
        String zoneUri = getZoneUri(subDomain, uaaUri);
        ConnectionDetails connectionDetails = buildConnectionDetails(zoneName, identityZone, zoneUri);
        return new OrchestratorZoneResponse(zoneName, zone, connectionDetails);
    }

    private String getSubDomainStr(IdentityZone identityZone) {
        String id = identityZone.getId();
        String subDomain = identityZone.getSubdomain();
        if(id.equals(subDomain)){
            subDomain = null;
        }
        return subDomain;
    }

    public void createOrchestratorZone(OrchestratorZoneRequest zoneRequest) throws OrchestratorZoneServiceException,
                                                                                   ZoneAlreadyExistsException,
                                                                                   AccessDeniedException {
        if (!IdentityZoneHolder.isUaa()) {
            throw new AccessDeniedException("Zones can only be created by being authenticated in the default zone.");
        }
        String name = zoneRequest.getName();
        String adminClientSecret = getAdminClientSecret(zoneRequest);

        checkOrchestratorZoneExists(name);

        String subdomain = zoneRequest.getParameters().getSubdomain();
        String id = UUID.randomUUID().toString();
        subdomain = getSubDomain(subdomain, id);

        String zoneSigningKey = createSigningKey(subdomain);

        IdentityZone identityZone = geIdentityZone(subdomain, name, id, zoneSigningKey);

        IdentityZone created = createIdentityZone(identityZone);

        if(created == null){
            throw new OrchestratorZoneServiceException("Error while create identity zone for subdomain : " + subdomain );
        }

        createDefaultIdp(created);

        createUserGroups(created);

        createClient(adminClientSecret, subdomain, id, created);
    }

    private String getAdminClientSecret(OrchestratorZoneRequest zoneRequest) throws OrchestratorZoneServiceException {
        String adminClientSecret = zoneRequest.getParameters().getAdminSecret();
        if (!StringUtils.hasText(adminClientSecret)) {
            throw new OrchestratorZoneServiceException(
                "The \"" + UAA_ADMIN_SECRET + "\" field cannot contain spaces or cannot be blank.");
        }
        return adminClientSecret;
    }

    private String getSubDomain(String subdomain, String id) throws OrchestratorZoneServiceException {
        String customSubdomain = getCustomSubdomain(subdomain);
        if (customSubdomain == null) {
            subdomain = id;
        } else {
            subdomain = customSubdomain;
        }
        return subdomain;
    }

    private void checkOrchestratorZoneExists(String name) throws ZoneAlreadyExistsException {
        IdentityZone identityZone = null;
        try{
            identityZone = zoneProvisioning.retrieveByName(name);
        } catch (ZoneDoesNotExistsException e){
            identityZone = null;
        }
        if(identityZone != null){
            throw new ZoneAlreadyExistsException("Orchestrator zone already exists for name:  " + name );
        }
    }

    private void createClient(String adminClientSecret, String subdomain, String id, IdentityZone created)
        throws OrchestratorZoneServiceException {
        String zoneId = IdentityZoneHolder.get().getId();
        String authorities = zoneAuthorities + ",zones." + zoneId + ".admin";
        try {
            createClient(created.getId(), authorities, clientId, adminClientSecret, grantTypes, resourceIds,
                         scopes);
        } catch (Exception e) {
            logger.error("Unable to create client for subdomain : " + subdomain + " Zone Id : " + zoneId + " Exception is :" + e.getMessage());
            throw new OrchestratorZoneServiceException("Unexpected exception while create client for " +
                                                       "subdomain : " + subdomain + " Zone Id : " + zoneId + " Exception is :" + e.getMessage());
        }
    }

    private void createDefaultIdp(IdentityZone created) throws OrchestratorZoneServiceException {
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
        } catch (Exception e) {
            logger.error("Unable to create identity provider for subdomain : " + created.getSubdomain() + " Exception " +
                         "is : " + e.getMessage());
            throw new OrchestratorZoneServiceException("Unexpected exception while create identity provider for " +
                                                       "subdomain : ." + created.getSubdomain() + " Exception is : " + e.getMessage());
        }
    }

    private IdentityZone createIdentityZone(IdentityZone identityZone)
        throws OrchestratorZoneServiceException {
        IdentityZone created = null;
        try {
            created = zoneProvisioning.create(identityZone);
        } catch (Exception e) {
            logger.error("Unable to create identity zone for subdomain : " + identityZone.getSubdomain() + " Exception is : " + e.getMessage());
            throw new OrchestratorZoneServiceException("Unexpected exception while create identity zone for " +
                                                       "subdomain : ." + identityZone.getSubdomain() + " Exception is : " + e.getMessage());
        }
        return created;
    }

    private IdentityZone geIdentityZone(String subdomain, String name, String id, String zoneSigningKey) throws OrchestratorZoneServiceException {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setName(name);
        identityZone.setSubdomain(subdomain);
        setTokenPolicy(zoneSigningKey, identityZone);
        setSamlConfig(subdomain, identityZone);
        identityZone.getConfig().getLinks().getLogout().setWhitelist(createDeploymentSpecificLogoutWhiteList());
        return identityZone;
    }

    private void setSamlConfig(String subdomain, IdentityZone identityZone) throws OrchestratorZoneServiceException {
        try {
            identityZone.getConfig().setSamlConfig(createSamlConfig(subdomain));
        } catch (Exception e) {
            logger.error("Unable to create saml config for subdomain: " + subdomain + " Exception is : " + e.getMessage());
            throw new OrchestratorZoneServiceException("Unexpected exception while create saml config for " +
                                                       "subdomain: ." + subdomain + " Exception is : " + e.getMessage());
        }
    }

    private void setTokenPolicy(String zoneSigningKey, IdentityZone identityZone) {
        String activeKeyId = new RandomValueStringGenerator(5).generate();
        Map<String, String> keys = getKeys(zoneSigningKey, activeKeyId);
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setActiveKeyId(activeKeyId);
        tokenPolicy.setKeys(keys);
        identityZone.getConfig().setTokenPolicy(tokenPolicy);
    }

    private String createSigningKey(String subdomain) throws OrchestratorZoneServiceException {
        String zoneSigningKey = "";
        try {
            zoneSigningKey = createSigningKey();
        } catch (Exception e) {
            logger.error("Unable to create signingKey for subdomain: " + subdomain + " Exception is : " + e.getMessage());
            throw new OrchestratorZoneServiceException("Unexpected exception while create signingKey for subdomain: " + subdomain);
        }
        return zoneSigningKey;
    }

    private String getCustomSubdomain(final String subdomain) throws OrchestratorZoneServiceException {
        if (subdomain == null) {
            return null;
        }
        String subDomain = subdomain;
        if (!StringUtils.hasText(subDomain)) {
            throw new OrchestratorZoneServiceException(
                "The \"" + UAA_CUSTOM_SUBDOMAIN + "\" field cannot contain spaces or cannot be blank.");
        }
        if (!SUBDOMAIN_PATTERN.matcher(subDomain).matches()) {
            throw new OrchestratorZoneServiceException("The \"" + UAA_CUSTOM_SUBDOMAIN
                                             + "\" is invalid. Special characters are not allowed in the subdomain name except hyphen which can be specified in the middle.");
        }
        return subDomain;
    }

    private BaseClientDetails syncWithExisting(BaseClientDetails existing, BaseClientDetails input) {
        BaseClientDetails details = input;
        BaseClientDetails baseInput = input;
        if (baseInput.getAutoApproveScopes()!=null) {
            details.setAutoApproveScopes(baseInput.getAutoApproveScopes());
        } else {
            details.setAutoApproveScopes(new HashSet<String>());
            BaseClientDetails existingDetails = existing;
            if (existingDetails.getAutoApproveScopes()!=null) {
                for (String scope : existingDetails.getAutoApproveScopes()) {
                    details.getAutoApproveScopes().add(scope);
                }
            }
        }

        if (details.getAccessTokenValiditySeconds() == null) {
            details.setAccessTokenValiditySeconds(existing.getAccessTokenValiditySeconds());
        }
        if (details.getRefreshTokenValiditySeconds() == null) {
            details.setRefreshTokenValiditySeconds(existing.getRefreshTokenValiditySeconds());
        }
        if (details.getAuthorities() == null || details.getAuthorities().isEmpty()) {
            details.setAuthorities(existing.getAuthorities());
        }
        if (details.getAuthorizedGrantTypes() == null || details.getAuthorizedGrantTypes().isEmpty()) {
            details.setAuthorizedGrantTypes(existing.getAuthorizedGrantTypes());
        }
        if (details.getRegisteredRedirectUri() == null || details.getRegisteredRedirectUri().isEmpty()) {
            details.setRegisteredRedirectUri(existing.getRegisteredRedirectUri());
        }
        if (details.getResourceIds() == null || details.getResourceIds().isEmpty()) {
            details.setResourceIds(existing.getResourceIds());
        }
        if (details.getScope() == null || details.getScope().isEmpty()) {
            details.setScope(existing.getScope());
        }

        Map<String, Object> additionalInformation = new HashMap<String, Object>(existing.getAdditionalInformation());
        additionalInformation.putAll(input.getAdditionalInformation());
        for (String key : Collections.unmodifiableSet(additionalInformation.keySet())) {
            if (additionalInformation.get(key) == null) {
                additionalInformation.remove(key);
            }
        }
        details.setAdditionalInformation(additionalInformation);

        return details;
    }

    private void createClient(final String id, final String authorities, final String clientId,
                              final String clientSecret,
                              final String grantTypes, final String resourceIds, final String scopes) {
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, resourceIds, scopes, grantTypes, authorities);
        clientDetails.setClientSecret(clientSecret);
        ClientDetails details = clientDetailsValidator.validate(clientDetails, Mode.CREATE);
        clientDetailsService.create(details, id);
    }

    public void createUserGroups(IdentityZone zone) {
        UserConfig userConfig = zone.getConfig().getUserConfig();
        if (userConfig != null) {
            List<String> defaultGroups = ofNullable(userConfig.getDefaultGroups()).orElse(Collections.emptyList());
            for (String group : defaultGroups) {
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

    private List<String>  createDeploymentSpecificLogoutWhiteList()
    {
        String runDomainFQDN = getRunDomainFromUAADomain();
        return (StringUtils.isEmpty(runDomainFQDN))  ? Collections.singletonList("http*://**") :
               Collections.singletonList("http*://**" + runDomainFQDN);
    }

    /**
     * Remove all characters till first dot
     * @return
     */
    private String getRunDomainFromUAADomain() {
        if (StringUtils.isEmpty(domainName))  return domainName;
        int firstDotIndex = domainName.indexOf('.');
        if (firstDotIndex == -1)  return org.apache.commons.lang3.StringUtils.EMPTY;
        return domainName.substring(firstDotIndex);
    }


    private Map<String, String> getKeys(String zoneSigningKey, String activeKeyId) {
        Map<String, String> keysMap = new HashMap<>();
        Map<String, Map<String, String>> keys = new HashMap<>();
        Map<String, String> signingKeyMap = new HashMap<>();
        signingKeyMap.put("signingKey", zoneSigningKey);
        String keysStr = JsonUtils.writeValueAsString(signingKeyMap);
        keysMap.put(activeKeyId, keysStr);
        return keysMap;
    }

    private String createSigningKey() throws NoSuchAlgorithmException, IOException {

        StringWriter pemStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(pemStringWriter);

        KeyPairGenerator keyPairGenerator = null;
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        pemWriter.writeObject(keyPairGenerator.genKeyPair().getPrivate());
        pemWriter.flush();
        pemWriter.close();
        return pemStringWriter.toString();
    }

    private SamlConfig createSamlConfig(String subdomain) throws IOException, NoSuchAlgorithmException, OperatorCreationException {
        JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder("DES-EDE3-CBC");
        builder.setProvider("BC");
        String passphrase = new RandomValueStringGenerator(8).generate();
        PEMEncryptor pemEncryptor = builder.build(passphrase.toCharArray());
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair kp = rsa.generateKeyPair();

        JcaMiscPEMGenerator pemGenerator = new JcaMiscPEMGenerator(kp.getPrivate(), pemEncryptor);
        StringWriter pemStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(pemStringWriter);
        pemWriter.writeObject(pemGenerator);
        pemWriter.flush();
        pemWriter.close();

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

        String certificate = BEGIN_CERT + "\n" + base64encoder.encode(certHolder.getEncoded()) + "\n" + END_CERT;
        samlKeys.put(GENERATED_KEY_ID, new SamlKey(pemStringWriter.toString(), passphrase, certificate));
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setKeys(samlKeys);
        samlConfig.setActiveKeyId(GENERATED_KEY_ID);

        return samlConfig;
    }

    private ConnectionDetails buildConnectionDetails(String zoneName, IdentityZone identityZone,
                                                            String zoneUri) {
        ConnectionDetails connectionDetails = new ConnectionDetails();
        connectionDetails.setUri(zoneUri);
        connectionDetails.setIssuerId(zoneUri + "/oauth/token");
        connectionDetails.setSubdomain(identityZone.getSubdomain());
        connectionDetails.setDashboardUri(uaaDashboardUri);
        OrchestratorZoneHeader zoneHeader = new OrchestratorZoneHeader(X_IDENTITY_ZONE_ID, identityZone.getId());
        connectionDetails.setZone(zoneHeader);
        return connectionDetails;
    }

    private String getZoneUri(String subdomain, String uaaUri) {
        URI uaaUriObject = URI.create(uaaUri);
        String currentUAAHostName = uaaUriObject.getHost();
        String replacement = subdomain + "." + currentUAAHostName;
        if (StringUtils.isEmpty(subdomain)) {
            replacement = currentUAAHostName;
        };
        URI newUAARoute = URI
            .create(uaaUriObject.toString().replace(currentUAAHostName, replacement));
        return newUAARoute.toString();
    }
}
