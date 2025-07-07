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

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api") // Base path for API endpoints
public class CspReportToController {

    private static final Logger logger = LoggerFactory.getLogger(CspReportToController.class);

    /**
     * API endpoint for receiving CSP violation reports sent via the 'report-to' directive
     * (part of the Reporting API).
     *
     * The browser typically sends 'application/reports+json' or 'application/json'.
     * The payload is an array of reports, even if there's only one.
     */
    @PostMapping(
            value = "/csp-reports", // This URL must match the 'url' in your 'Report-To' HTTP header
            consumes = {MediaType.APPLICATION_JSON_VALUE, "application/reports+json"}
    )
    public ResponseEntity<Void> handleCspReports(
            @RequestBody List<Map<String, Object>> reportsPayload, // Expects an array of reports
            HttpServletRequest request) {

        logger.warn("Received CSP Report-To Violation from {}. Total reports: {}",
                request.getRemoteAddr(),
                reportsPayload != null ? reportsPayload.size() : 0);

        if (reportsPayload != null) {
            for (Map<String, Object> report : reportsPayload) {
                // The actual violation details for 'report-to' are typically nested under a "body" field
                Map<String, Object> body = (Map<String, Object>) report.get("body");
                String type = (String) report.get("type"); // e.g., "csp-violation"

                if ("csp-violation".equals(type) && body != null) {
                    String documentUrl = (String) body.get("documentUrl");
                    String violatedDirective = (String) body.get("violatedDirective");
                    String blockedURL = (String) body.get("blockedURL");
                    String originalPolicy = (String) body.get("originalPolicy");
                    String disposition = (String) body.get("disposition"); // "report" or "enforce"

                    logger.warn("  Report-To Details: Doc URL='{}', Violated Directive='{}', Blocked URL='{}', Policy='{}', Disposition='{}'",
                            documentUrl, violatedDirective, blockedURL, originalPolicy, disposition);

                    // TODO: Implement your persistent storage logic here for this report
                } else {
                    logger.warn("  Received non-CSP or malformed report-to payload: Type={}, Payload={}", type, report);
                }
            }
        } else {
            logger.error("Received null or empty CSP Report-To payload.");
        }

        // Return 204 No Content, indicating successful receipt without a response body.
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}