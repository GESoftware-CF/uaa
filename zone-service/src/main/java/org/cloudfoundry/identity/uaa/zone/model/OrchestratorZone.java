package org.cloudfoundry.identity.uaa.zone.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import javax.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(Include.NON_NULL)
public class OrchestratorZone {

    @NotBlank(message = org.cloudfoundry.identity.uaa.zone.OrchestratorZoneController.MANDATORY_VALIDATION_MESSAGE)
    private String adminSecret;

    private String subdomain = null;
}
