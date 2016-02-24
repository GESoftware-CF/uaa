package org.cloudfoundry.identity.uaa.provider.token;

import java.util.Map;

import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;
import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;

public class MockPublicKeyProvider implements DevicePublicKeyProvider {

    @Override
    public String getPublicKey(String tenantId, String deviceId) throws PublicKeyNotFoundException {
        return TestKeys.TOKEN_VERIFYING_KEY;
    }

}
