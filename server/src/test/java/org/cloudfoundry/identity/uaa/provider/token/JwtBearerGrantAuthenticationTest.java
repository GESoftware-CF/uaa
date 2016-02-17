package org.cloudfoundry.identity.uaa.provider.token;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpRequest;
import org.springframework.security.core.Authentication;

public class JwtBearerGrantAuthenticationTest {

    private JwtBearerGrantAuthenticationProvider jwtBearerGrantAuthenticationProvider;

    @Test
    public void testSuccessfulClientAuthentication() {
        Authentication expected;
        HttpRequest request;
        Assert.assertEquals(expected, jwtBearerGrantAuthenticationProvider.authenticate(request));
    }
}
