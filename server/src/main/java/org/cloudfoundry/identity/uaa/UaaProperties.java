package org.cloudfoundry.identity.uaa;

import lombok.Getter;
import lombok.Setter;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "uaa")
@Getter
@Setter
public class UaaProperties {

    private String url = UaaStringUtils.DEFAULT_UAA_URL;

}
