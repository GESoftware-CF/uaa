package org.cloudfoundry.identity.uaa.csp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest; // Use javax.servlet for Spring Boot 2.6.x
import java.util.Map;

@RestController
@RequestMapping("/api")
public class CspReportUriController {

    private static final Logger logger = LoggerFactory.getLogger(CspReportUriController.class);

    /**
     * API endpoint for receiving CSP violation reports sent via the older 'report-uri' directive.
     * The browser sends a POST request with Content-Type: application/json.
     * The payload is a single JSON object with a "csp-report" key.
     */
    @PostMapping(value = "/csp-report-uri", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> handleCspReportUri(
            @RequestBody Map<String, Object> cspReportPayload, // Expects a single Map
            HttpServletRequest request) {

        logger.warn("Received CSP report-uri Violation from {}: {}",
                request.getRemoteAddr(),
                cspReportPayload);

        // For report-uri, the actual violation details are typically nested under a "csp-report" key
        Map<String, Object> cspReport = (Map<String, Object>) cspReportPayload.get("csp-report");

        if (cspReport != null) {
            String documentUri = (String) cspReport.get("document-uri");
            String violatedDirective = (String) cspReport.get("violated-directive");
            String blockedUri = (String) cspReport.get("blocked-uri");
            String originalPolicy = (String) cspReport.get("original-policy");

            logger.warn("  Report-URI Details: Doc URI='{}', Violated Directive='{}', Blocked URI='{}', Policy='{}'",
                    documentUri, violatedDirective, blockedUri, originalPolicy);

            // TODO: Implement your persistent storage logic here for this report
        } else {
            logger.error("Received malformed CSP report-uri payload: 'csp-report' key missing.");
        }

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}