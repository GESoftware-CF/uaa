package org.cloudfoundry.identity.uaa.csp;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CspReportToPayload {
    private Integer age;
    private String type; // e.g., "csp-violation"
    private String url; // The document URL from the outer report object
    private Body body;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Body {
        private String blockedURL; // Note: different capitalization than report-uri
        private String disposition;
        private String documentUrl;
        private String effectiveDirective;
        private String originalPolicy;
        private String referrer;
        private Integer statusCode;
        private String violatedDirective;
        private String sourceFile;
        private Integer lineNumber;
        private Integer columnNumber;
        private String sample;
    }
}