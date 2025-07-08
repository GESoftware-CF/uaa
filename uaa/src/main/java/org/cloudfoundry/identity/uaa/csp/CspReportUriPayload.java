package org.cloudfoundry.identity.uaa.csp;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CspReportUriPayload {

    @JsonProperty("csp-report")
    private CspReportUriDetails cspReport;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CspReportUriDetails {

        @JsonProperty("document-uri")
        private String documentUri;
        private String referrer;
        @JsonProperty("violated-directive")
        private String violatedDirective;
        @JsonProperty("effective-directive")
        private String effectiveDirective;
        @JsonProperty("original-policy")
        private String originalPolicy;
        @JsonProperty("blocked-uri")
        private String blockedUri;
        @JsonProperty("status-code")
        private Integer statusCode;
        @JsonProperty("source-file")
        private String sourceFile;
        @JsonProperty("line-number")
        private Integer lineNumber;
        @JsonProperty("column-number")
        private Integer columnNumber;
        @JsonProperty("script-sample")
        private String scriptSample;
    }
}