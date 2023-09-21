//package com.ge.predix.servicebroker.service;
//
//import java.io.IOException;
//import java.io.StringWriter;
//import java.math.BigInteger;
//import java.net.URI;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.NoSuchAlgorithmException;
//import java.util.*;
//import java.util.regex.Pattern;
//
//import com.ge.predix.servicebroker.client.uaa.IdentityZoneConfiguration.TokenPolicy;
//import com.ge.predix.servicebroker.client.uaa.SamlConfig;OAUTH_CLIENT_URI
//import com.ge.predix.servicebroker.client.uaa.SamlKey;
//import org.bouncycastle.asn1.x500.X500Name;
//import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
//import org.bouncycastle.cert.X509CertificateHolder;
//import org.bouncycastle.openssl.PEMEncryptor;
//import org.bouncycastle.cert.X509v1CertificateBuilder;
//import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
//import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
//import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
//import org.bouncycastle.operator.OperatorCreationException;
//import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
//import org.cloudfoundry.community.servicebroker.exception.ServiceBrokerException;
//import org.cloudfoundry.community.servicebroker.model.CreateServiceInstanceRequest;
//import org.cloudfoundry.community.servicebroker.model.DeleteServiceInstanceRequest;
//import org.cloudfoundry.community.servicebroker.model.UpdateServiceInstanceRequest;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.InitializingBean;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Qualifier;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.http.HttpEntity;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpMethod;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.MediaType;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.oauth2.client.OAuth2RestTemplate;
//import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
//import org.springframework.security.oauth2.provider.client.BaseClientDetails;
//import org.springframework.stereotype.Component;
//import org.springframework.util.StringUtils;
//import org.springframework.web.client.HttpClientErrorException;
//
//import com.ge.predix.servicebroker.client.uaa.IdentityZone;
//import sun.misc.BASE64Encoder;
//import sun.security.provider.X509Factory;
//
//import static com.ge.predix.servicebroker.client.uaa.SamlConfig.GENERATED_KEY_ID;
//import static java.security.Security.addProvider;
//
///**
// *
// * @author 212406427
// */
//@Component
//public class UaaZoneProvisioner implements SecurityZoneProvisioner, InitializingBean {
//
//    private static final Logger LOGGER = LoggerFactory.getLogger(UaaZoneProvisioner.class);
//    private static final String OAUTH_CLIENT_URI = "/oauth/clients";
//    public static final String ZONE_REL_URI = "/identity-zones";
//    public static final String UAA_ADMIN_CLIENT_SECRET = "adminClientSecret";
//    public static final String UAA_CUSTOM_SUBDOMAIN = "subdomain";
//    private static final String SUBDOMAIN_REGEX = "(?:[A-Za-z0-9][A-Za-z0-9\\-]{0,61}[A-Za-z0-9]|[A-Za-z0-9])";
//    private static final Pattern SUBDOMAIN_PATTERN;
//
//    @Value("${UAA_URI}")
//    private String uaaURI;
//
//    @Value("${UAA_DOMAIN_NAME}")
//    private String domainName;
//
//    @Autowired
//    @Qualifier("uaaClient")
//    private OAuth2RestTemplate uaaOauth2RestTemplate;
//
//    @Value("${CLOUD_CONTROLLER_URI}")
//    private String cloudControllerURI;
//
//    @Value("${UAA_CLIENT_ID}")
//    private String uaaClientID;
//
//    @Value("${CF_PASSWORD}")
//    private String cfPassword;
//
//    @Value("${CF_USERNAME}")
//    private String cfEmail;
//
//    @Value("${CF_SPACE}")
//    private String uaaSpaceName;
//
//    @Value("${CF_ORG}")
//    private String uaaOrgName;
//
//    @Value("${UAA_APP_NAME}")
//    private String appName;
//
//    @Value("${ZONE_CLIENT_NAME:admin}")
//    private String zoneClientId;
//
//    @Value("${ZONE_AUTHORITIES:clients.admin,clients.read,clients.write,clients.secret,idps.read,idps.write,"
//            + "sps.read,sps.write,scim.read,scim.write,uaa.resource}")
//    private String zoneAuthorities;
//
//    @Value("${ZONE_SCOPES:uaa.none}")
//    private String zoneScopes;
//
//    @Value("${ZONE_GRANT_TYPES:client_credentials}")
//    private String zoneGrantTypes;
//
//    @Value("${ZONE_RESOURCE_IDS:none}")
//    private String zoneResourceIds;
//
//    @Value("${ZONE_CLI_CLIENT_NAME:cli}")
//    private String zoneCliClientId;
//
//    @Value("${ZONE_CLI_CLIENT_SECRET:ch@ng3mE}")
//    private String zoneCliClientSecret;
//
//    @Value("${ZONE_CLI_AUTHORITIES:clients.secret,uaa.resource}")
//    private String zoneCliAuthorities;
//
//    @Value("${ZONE_CLI_SCOPES:clients.admin,clients.read,clients.write,clients.secret,idps.read,idps.write,openid,"
//            + "scim.read,scim.write}")
//    private String zoneCliScopes;
//
//    @Value("${ZONE_CLI_GRANT_TYPES:client_credentials,password}")
//    private String zoneCliGrantTypes;
//
//    @Value("${ZONE_CLI_RESOURCE_IDS:none}")
//    private String zoneCliResourceIds;
//
//    static {
//        SUBDOMAIN_PATTERN = Pattern.compile(SUBDOMAIN_REGEX);
//    }
//
//    @Override
//    public void afterPropertiesSet() {
//        addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//    }
//
//
//    @Override
//    public void provisionZone(final CreateServiceInstanceRequest createServiceInstanceRequest)
//            throws ServiceBrokerException, NoSuchAlgorithmException, OperatorCreationException, IOException {
//
//        LOGGER.info("UAA App Name is: " + this.appName + "; UAA URL: " + this.uaaURI);
//        String adminClientSecret = getAdminClientSecret(createServiceInstanceRequest);
//        URI uri = URI.create(this.uaaURI + ZONE_REL_URI);
//        String id = createServiceInstanceRequest.getServiceInstanceId();
//        String name = id;
//        String subdomain;
//        String customSubdomain = getCustomSubdomain(createServiceInstanceRequest);
//        if (customSubdomain == null) {
//            subdomain = name;
//        } else {
//            subdomain = customSubdomain;
//        }
//        String zoneSigningKey;
//        try {
//            zoneSigningKey = createSigningKey();
//        } catch (Exception e) {
//            LOGGER.error("Unable to create signingKey for subdomain: " + customSubdomain + "Exception is : " + e.getStackTrace());
//            throw new ServiceBrokerException("Unexpected exception while creating an UAA service instance.");
//        }
//        IdentityZone identityZone = new IdentityZone(id, name, subdomain);
//
//        String activeKeyId = new RandomValueStringGenerator(5).generate();
//        Map<String, Map<String, String>> keys = getKeys(zoneSigningKey, activeKeyId);
//        identityZone.getConfig().setTokenPolicy(new TokenPolicy(activeKeyId, keys));
//        identityZone.getConfig().setSamlConfig(createSamlConfig(subdomain));
//        identityZone.getConfig().getLinks().getLogout().setWhitelist(createDeploymentSpecificLogoutWhiteList());
//
//        HttpHeaders headers = new HttpHeaders();
//        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
//
//        HttpEntity<IdentityZone> requestEntity = new HttpEntity<IdentityZone>(identityZone, headers);
//        try {
//            ResponseEntity<IdentityZone> response = this.uaaOauth2RestTemplate.exchange(uri, HttpMethod.POST, requestEntity,
//                    IdentityZone.class);
//
//        } catch (Exception e) {
//            if (e.getMessage().contains("409")) {
//                throw new ServiceBrokerException("The \"" + UAA_CUSTOM_SUBDOMAIN
//                        + "\" name is already taken. Please use a different subdomain.");
//            } else {
//                LOGGER.info("Exception while creating an UAA service instance :" + e.getStackTrace());
//                throw new ServiceBrokerException("Unexpected exception while creating an UAA service instance.");
//            }
//        }
//
//        SimpleGrantedAxuthority authority = new SimpleGrantedAuthority("zones." + id + ".admin");
//        List<SimpleGrantedAuthority> tempAuthorityList = Arrays.asList(new SimpleGrantedAuthority[] { authority });
//        List<SimpleGrantedAuthority> emptyAuthorityList = Arrays.asList(new SimpleGrantedAuthority[] {});
//
//        this.updateDefaultAdminAuthorities(tempAuthorityList, emptyAuthorityList);
//        try {
//            this.createZoneAdminClient(createServiceInstanceRequest, adminClientSecret);
//        } finally {
//            this.updateDefaultAdminAuthorities(emptyAuthorityList, tempAuthorityList);
//        }
//    }
//
//    List<String>  createDeploymentSpecificLogoutWhiteList()
//    {
//        String runDomainFQDN = getRunDomainFromUAADomain();
//        return (StringUtils.isEmpty(runDomainFQDN))  ? Collections.singletonList("http*://**") :
//                Collections.singletonList("http*://**" + runDomainFQDN);
//    }
//
//    /**
//     * Remove all characters till first dot
//     * @return
//     */
//    private String getRunDomainFromUAADomain() {
//        if (StringUtils.isEmpty(domainName))  return domainName;
//        int firstDotIndex = domainName.indexOf('.');
//        if (firstDotIndex == -1)  return org.apache.commons.lang3.StringUtils.EMPTY;
//        return domainName.substring(firstDotIndex);
//    }
//
//    private Map<String, Map<String, String>> getKeys(String zoneSigningKey, String activeKeyId) {
//        Map<String, Map<String, String>> keys = new HashMap<>();
//        Map<String, String> signingKeyMap = new HashMap<>();
//        signingKeyMap.put("signingKey", zoneSigningKey);
//        keys.put(activeKeyId, signingKeyMap);
//        return keys;
//    }
//
//    private String createSigningKey() throws NoSuchAlgorithmException, IOException {
//
//        StringWriter pemStringWriter = new StringWriter();
//        JcaPEMWriter pemWriter = new JcaPEMWriter(pemStringWriter);
//
//        KeyPairGenerator keyPairGenerator = null;
//        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048);
//        pemWriter.writeObject(keyPairGenerator.genKeyPair().getPrivate());
//        pemWriter.flush();
//        pemWriter.close();
//        return pemStringWriter.toString();
//    }
//
//    private SamlConfig createSamlConfig(String subdomain) throws IOException, NoSuchAlgorithmException, OperatorCreationException {
//        JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder("DES-EDE3-CBC");
//        builder.setProvider("BC");
//        String passphrase = new RandomValueStringGenerator(8).generate();
//        PEMEncryptor pemEncryptor = builder.build(passphrase.toCharArray());
//        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
//        rsa.initialize(2048);
//        KeyPair kp = rsa.generateKeyPair();
//
//        JcaMiscPEMGenerator pemGenerator = new JcaMiscPEMGenerator(kp.getPrivate(), pemEncryptor);
//        StringWriter pemStringWriter = new StringWriter();
//        JcaPEMWriter pemWriter = new JcaPEMWriter(pemStringWriter);
//        pemWriter.writeObject(pemGenerator);
//        pemWriter.flush();
//        pemWriter.close();
//
//        Calendar cal = Calendar.getInstance();
//        cal.add(Calendar.YEAR, 10);
//
//        byte[] pk = kp.getPublic().getEncoded();
//        SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(pk);
//        String dn = "C=US, ST=CA, L=San Ramon, O=GE, OU=GE Digital, CN=PredixUAA"+subdomain;
//        X509v1CertificateBuilder certGen = new X509v1CertificateBuilder(
//                new X500Name(dn),
//                BigInteger.ONE,
//                new Date(),
//                cal.getTime(),
//                new X500Name(dn),
//                bcPk
//        );
//        X509CertificateHolder certHolder = certGen
//                .build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));
//        BASE64Encoder encoder = new BASE64Encoder();
//
//        HashMap<String, SamlKey> samlKeys = new HashMap<>();
//
//        String certificate = X509Factory.BEGIN_CERT + "\n" + encoder.encode(certHolder.getEncoded()) + "\n" + X509Factory.END_CERT;
//        samlKeys.put(GENERATED_KEY_ID, new SamlKey(pemStringWriter.toString(), passphrase, certificate));
//        SamlConfig samlConfig = new SamlConfig();
//        samlConfig.setKeys(samlKeys);
//        samlConfig.setActiveKeyId(GENERATED_KEY_ID);
//
//        return samlConfig;
//    }
//
//    private String getAdminClientSecret(final CreateServiceInstanceRequest request) throws ServiceBrokerException {
//        Map<String, Object> parameters = request.getParameters();
//        if (parameters == null || (parameters.get(UAA_ADMIN_CLIENT_SECRET) == null)) {
//            throw new ServiceBrokerException(
//                    "The \"" + UAA_ADMIN_CLIENT_SECRET + "\" field is required to create a UAA instance");
//        }
//
//        return (String) parameters.get(UAA_ADMIN_CLIENT_SECRET);
//    }
//
//    private String getCustomSubdomain(final CreateServiceInstanceRequest request) throws ServiceBrokerException {
//        Map<String, Object> parameters = request.getParameters();
//        if (parameters.get(UAA_CUSTOM_SUBDOMAIN) == null) {
//            return null;
//        }
//        String subdomain = (String) parameters.get(UAA_CUSTOM_SUBDOMAIN);
//        if (!StringUtils.hasText(subdomain)) {
//            throw new ServiceBrokerException(
//                    "The \"" + UAA_CUSTOM_SUBDOMAIN + "\" field cannot contain spaces or cannot be blank.");
//        }
//        if (!SUBDOMAIN_PATTERN.matcher(subdomain).matches()) {
//            throw new ServiceBrokerException("The \"" + UAA_CUSTOM_SUBDOMAIN
//                    + "\" is invalid. Special characters are not allowed in the subdomain name except hyphen which can be specified in the middle.");
//        }
//        return subdomain;
//    }
//
//    public void updateDefaultAdminAuthorities(final List<SimpleGrantedAuthority> addAuthorities,
//                                              final List<SimpleGrantedAuthority> removeAuthorities) {
//        URI uri = URI.create(this.uaaURI + OAUTH_CLIENT_URI + "/" + this.uaaClientID);
//
//        BaseClientDetails baseClientDetails = this.uaaOauth2RestTemplate.getForObject(uri, BaseClientDetails.class);
//        Collection<GrantedAuthority> authorities = baseClientDetails.getAuthorities();
//
//        authorities.addAll(addAuthorities);
//        authorities.removeAll(removeAuthorities);
//
//        HttpHeaders headers = new HttpHeaders();
//        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
//        baseClientDetails.setAuthorities(authorities);
//        this.uaaOauth2RestTemplate.put(uri, baseClientDetails);
//
//        // Set the token to null to ensure new token is fetched.
//        this.uaaOauth2RestTemplate.getOAuth2ClientContext().setAccessToken(null);
//    }
//
//    private void createZoneAdminClient(final CreateServiceInstanceRequest createServiceInstanceRequest,
//                                       final String adminClientSecret) {
//        String serviceInstanceId = createServiceInstanceRequest.getServiceInstanceId();
//
//        String clientId = this.zoneClientId;
//        String authorities = getZoneClientPrivileges(this.zoneAuthorities, serviceInstanceId);
//        String grantTypes = this.zoneGrantTypes;
//        String resourceIds = this.zoneResourceIds;
//        String scopes = this.zoneScopes;
//
//        createClient(serviceInstanceId, authorities, clientId, adminClientSecret, grantTypes, resourceIds, scopes);
//    }
//
//    private void createClient(final String serviceInstanceId, final String authorities, final String clientId,
//                              final String clientSecret, final String grantTypes, final String resourceIds, final String scopes) {
//        BaseClientDetails client = new BaseClientDetails(clientId, resourceIds, scopes, grantTypes, authorities);
//        client.setClientSecret(clientSecret);
//
//        URI currentURI = URI.create(this.uaaURI + OAUTH_CLIENT_URI);
//
//        LOGGER.debug("BaseClient Details for the zone admin client are " + client.getClientId());
//        LOGGER.debug("URI to create the zone client is " + currentURI.toString());
//
//        HttpHeaders headers = new HttpHeaders();
//        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
//        headers.add("X-Identity-Zone-Id", serviceInstanceId);
//
//        HttpEntity<BaseClientDetails> requestEntity = new HttpEntity<>(client, headers);
//        this.uaaOauth2RestTemplate.postForEntity(currentURI, requestEntity, BaseClientDetails.class);
//    }
////
////    public String getZoneCliClientAdminName(final String serviceInstanceId) {
////        return serviceInstanceId + "-" + this.zoneCliClientId;
////    }
//
//    private String getZoneClientPrivileges(final String zoneClientAuthorities, final String zoneId) {
//        return zoneClientAuthorities + ",zones." + zoneId + ".admin";
//    }
//
//    @Override
//    public void deleteZone(final DeleteServiceInstanceRequest deleteServiceInstanceRequest) throws Exception {
//        String zoneName = deleteServiceInstanceRequest.getServiceInstanceId();
//        URI zoneAdminUaaURI = URI.create(this.uaaURI + ZONE_REL_URI + "/" + zoneName);
//        try {
//            this.uaaOauth2RestTemplate.delete(zoneAdminUaaURI);
//            LOGGER.info("Deleted the UAA Zone: " + zoneName);
//        } catch (HttpClientErrorException e) {
//            if (e.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
//                LOGGER.info("Unable to find the zone, continuing with the service deletion. ZoneName: " + zoneName );
//            } else {
//                throw e;
//            }
//        }
//        return;
//    }
//
//    @Override
//    public void updateZone(final UpdateServiceInstanceRequest updateServiceInstanceRequest,
//                           final String serviceDefinitionId) throws Exception {
//        throw new ServiceBrokerException("Updating \"adminClientSecret\" for UAA instance is not supported.");
//    }
//}