package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class KeyProviderValidatorTest {

    KeyProviderValidator keyProviderValidator;
    ClientDetailsService mockClients = Mockito.mock(ClientDetailsService.class);

    @Rule
    public ExpectedException expection = ExpectedException.none();

    @Before
    public void setup() {
        keyProviderValidator = new KeyProviderValidator();
        keyProviderValidator.setClientDetailsService(mockClients);
    }

    @Test
    public void testValidate() throws KeyProviderValidator.KeyProviderValidatorException {
        when(mockClients.loadClientByClientId(eq("valid-client-id"))).thenReturn(new UaaClientDetails());
        KeyProviderConfig test = new KeyProviderConfig("valid-client-id", "anything");
        keyProviderValidator.validate(test);
    }

    @Test
    public void testValidateEmptyClientId() throws KeyProviderValidator.KeyProviderValidatorException {
        when(mockClients.loadClientByClientId(anyString())).thenReturn(new UaaClientDetails());
        KeyProviderConfig test = new KeyProviderConfig("", "anything");
        expection.expect(KeyProviderValidator.KeyProviderValidatorException.class);
        expection.expectMessage("Empty client id.");
        keyProviderValidator.validate(test);
    }

    @Test
    public void testValidateEmptyTenantId() throws KeyProviderValidator.KeyProviderValidatorException {
        when(mockClients.loadClientByClientId(anyString())).thenReturn(new UaaClientDetails());
        KeyProviderConfig test = new KeyProviderConfig("anything", "");
        expection.expect(KeyProviderValidator.KeyProviderValidatorException.class);
        expection.expectMessage("Empty tenant id.");
        keyProviderValidator.validate(test);
    }

    @Test
    public void testValidateClientNotFound() throws KeyProviderValidator.KeyProviderValidatorException {
        when(mockClients.loadClientByClientId(anyString())).thenThrow(new NoSuchClientException("I dunno man, it's in the title"));
        KeyProviderConfig test = new KeyProviderConfig("nonexistent-client-id","anything");
        expection.expect(KeyProviderValidator.KeyProviderValidatorException.class);
        expection.expectMessage("Client nonexistent-client-id was not found.");
        keyProviderValidator.validate(test);
    }
}