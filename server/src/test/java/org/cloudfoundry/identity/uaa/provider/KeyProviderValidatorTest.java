package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class KeyProviderValidatorTest {

    KeyProviderValidator keyProviderValidator;
    ClientDetailsService mockClients = Mockito.mock(ClientDetailsService.class);

    @Before
    public void setup() {
        keyProviderValidator = new KeyProviderValidator();
        keyProviderValidator.setClientDetailsService(mockClients);
    }

    @Test
    public void testValidate() throws Exception {
        when(mockClients.loadClientByClientId(eq("valid-client-id"))).thenReturn(new UaaClientDetails());
        KeyProviderConfig test = new KeyProviderConfig("valid-client-id", "anything");
        keyProviderValidator.validate(test); // no exception expected
    }

    @Test
    public void testValidateEmptyClientId() {
        when(mockClients.loadClientByClientId(anyString())).thenReturn(new UaaClientDetails());
        KeyProviderConfig test = new KeyProviderConfig("", "anything");
        KeyProviderValidator.KeyProviderValidatorException ex =
                Assert.assertThrows(
                        KeyProviderValidator.KeyProviderValidatorException.class,
                        () -> keyProviderValidator.validate(test)
                );
        Assert.assertEquals("Empty client id.", ex.getMessage());
    }

    @Test
    public void testValidateEmptyTenantId() {
        when(mockClients.loadClientByClientId(anyString())).thenReturn(new UaaClientDetails());
        KeyProviderConfig test = new KeyProviderConfig("anything", "");
        KeyProviderValidator.KeyProviderValidatorException ex =
                Assert.assertThrows(
                        KeyProviderValidator.KeyProviderValidatorException.class,
                        () -> keyProviderValidator.validate(test)
                );
        Assert.assertEquals("Empty tenant id.", ex.getMessage());
    }

    @Test
    public void testValidateClientNotFound() {
        when(mockClients.loadClientByClientId(anyString()))
                .thenThrow(new NoSuchClientException("I dunno man, it's in the title"));
        KeyProviderConfig test = new KeyProviderConfig("nonexistent-client-id", "anything");
        KeyProviderValidator.KeyProviderValidatorException ex =
                Assert.assertThrows(
                        KeyProviderValidator.KeyProviderValidatorException.class,
                        () -> keyProviderValidator.validate(test)
                );
        Assert.assertEquals("Client nonexistent-client-id was not found.", ex.getMessage());
    }
}