package org.cloudfoundry.identity.uaa.config;

import jakarta.annotation.PostConstruct;
import org.apache.coyote.ProtocolHandler;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.coyote.http11.Http11NioProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Logs effective Tomcat connector and protocol configuration at startup.
 *
 * <p>Runs after Spring Boot's default Tomcat customizer so logged values reflect
 * final effective values.
 */
@Component
@Order(1)
public class TomcatConfigLogger implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    private static final Logger LOGGER = LoggerFactory.getLogger(TomcatConfigLogger.class);

    private final Environment env;

    public TomcatConfigLogger(Environment env) {
        this.env = env;
    }

    @PostConstruct
    public void onInit() {
        LOGGER.info("TomcatConfigLogger bean initialized");
        String keepAliveTimeout = env.getProperty("server.tomcat.keep-alive-timeout");
        String maxKeepAliveRequests = env.getProperty("server.tomcat.max-keep-alive-requests");

        LOGGER.info(
                "Spring resolved server.tomcat.keep-alive-timeout={}",
                keepAliveTimeout != null ? keepAliveTimeout : "NOT SET"
        );
        LOGGER.info(
                "Spring resolved server.tomcat.max-keep-alive-requests={}",
                maxKeepAliveRequests != null ? maxKeepAliveRequests : "NOT SET"
        );
    }

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        factory.addConnectorCustomizers(connector -> {
            LOGGER.info("Tomcat connector properties:");
            LOGGER.info("port={}", connector.getPort());
            LOGGER.info("maxKeepAliveRequests (connector property)={}",
                    connector.getProperty("maxKeepAliveRequests"));
            LOGGER.info("keepAliveTimeout (connector property)={}",
                    connector.getProperty("keepAliveTimeout"));
            LOGGER.info("connectionTimeout (connector property)={}",
                    connector.getProperty("connectionTimeout"));

            ProtocolHandler handler = connector.getProtocolHandler();
            LOGGER.info("protocolHandler class={}", handler.getClass().getName());

            if (handler instanceof Http11NioProtocol protocol) {
                logHttp11Values(protocol);
            } else if (handler instanceof AbstractHttp11Protocol<?> protocol) {
                logHttp11Values(protocol);
            } else {
                LOGGER.info("ProtocolHandler is not Http11 protocol, skipping keep-alive getter logs.");
            }
        });
    }

    private void logHttp11Values(AbstractHttp11Protocol<?> protocol) {
        LOGGER.info("Tomcat protocol values:");
        LOGGER.info("maxKeepAliveRequests={}", protocol.getMaxKeepAliveRequests());
        LOGGER.info("keepAliveTimeout={}", protocol.getKeepAliveTimeout());
        LOGGER.info("connectionTimeout={}", protocol.getConnectionTimeout());
        LOGGER.info("compression={}", protocol.getCompression());
        LOGGER.info("compressionMimeTypes={}", protocol.getCompressibleMimeType());
    }
}
