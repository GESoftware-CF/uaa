package org.cloudfoundry.identity.uaa;

import jakarta.annotation.PostConstruct;
import org.apache.coyote.ProtocolHandler;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.coyote.http11.Http11NioProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.lang.management.ManagementFactory;
import java.util.Set;

/**
 * Logs effective Tomcat connector and protocol configuration at startup.
 *
 * <p>Uses two strategies:
 * <ul>
 *   <li>{@link WebServerFactoryCustomizer} — fires only for embedded Tomcat.</li>
 *   <li>{@link ApplicationListener} querying JMX MBeans — works for both embedded
 *       and external/Cargo Tomcat deployments (WAR).</li>
 * </ul>
 */
@Component
public class TomcatConfigLogger
        implements WebServerFactoryCustomizer<TomcatServletWebServerFactory>,
                   ApplicationListener<ContextRefreshedEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(TomcatConfigLogger.class);

    private final Environment env;

    /** Guard against duplicate logging on child context refreshes. */
    private volatile boolean jmxLogged = false;

    public TomcatConfigLogger(final Environment env) {
        this.env = env;
    }

    // -------------------------------------------------------------------------
    // @PostConstruct — logs Spring-resolved property values (always fires)
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // WebServerFactoryCustomizer — only fires for embedded Tomcat
    // -------------------------------------------------------------------------

    @Override
    public void customize(final TomcatServletWebServerFactory factory) {
        factory.addConnectorCustomizers(connector -> {
            LOGGER.info("=== Tomcat Embedded Connector (customize) ===");
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
                LOGGER.info("ProtocolHandler is not Http11 — skipping keep-alive getter logs.");
            }
            LOGGER.info("=== End Tomcat Embedded Connector ===");
        });
    }

    // -------------------------------------------------------------------------
    // ApplicationListener<ContextRefreshedEvent> — fires for embedded AND
    // external/Cargo Tomcat; reads actual live values via JMX MBeans
    // -------------------------------------------------------------------------

    @Override
    public void onApplicationEvent(final ContextRefreshedEvent event) {
        if (jmxLogged) {
            return; // prevent duplicate logging on child context refreshes
        }
        jmxLogged = true;
        logTomcatConnectorsViaJmx();
    }

    /**
     * Reads Tomcat connector attributes from JMX MBeans.
     *
     * <p>Works for both embedded Tomcat and WAR deployed to external Tomcat (Cargo),
     * because Tomcat registers connector MBeans under {@code Catalina:type=Connector,*}
     * regardless of deployment mode.
     */
    private void logTomcatConnectorsViaJmx() {
        try {
            MBeanServer mBeanServer = ManagementFactory.getPlatformMBeanServer();
            Set<ObjectName> connectorNames = mBeanServer.queryNames(
                    new ObjectName("Catalina:type=Connector,*"), null);

            if (connectorNames.isEmpty()) {
                LOGGER.warn("No Tomcat Connector MBeans found under 'Catalina:type=Connector,*'. "
                        + "JMX may not be enabled or Tomcat has not finished starting yet.");
                return;
            }

            for (ObjectName name : connectorNames) {
                LOGGER.info("=== Tomcat Connector MBean: {} ===", name);
                logMBeanAttribute(mBeanServer, name, "port");
                logMBeanAttribute(mBeanServer, name, "maxKeepAliveRequests");
                logMBeanAttribute(mBeanServer, name, "keepAliveTimeout");
                logMBeanAttribute(mBeanServer, name, "connectionTimeout");
                logMBeanAttribute(mBeanServer, name, "compression");
                logMBeanAttribute(mBeanServer, name, "compressibleMimeType");
                logMBeanAttribute(mBeanServer, name, "maxConnections");
                logMBeanAttribute(mBeanServer, name, "maxThreads");
                LOGGER.info("=== End Connector MBean: {} ===", name);
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to read Tomcat connector config via JMX: {}", e.getMessage(), e);
        }
    }

    private void logMBeanAttribute(final MBeanServer server, final ObjectName name,
                                   final String attribute) {
        try {
            Object value = server.getAttribute(name, attribute);
            LOGGER.info("  {}={}", attribute, value);
        } catch (Exception e) {
            LOGGER.debug("  {} not available: {}", attribute, e.getMessage());
        }
    }

    private void logHttp11Values(final AbstractHttp11Protocol<?> protocol) {
        LOGGER.info("Tomcat protocol values:");
        LOGGER.info("maxKeepAliveRequests={}", protocol.getMaxKeepAliveRequests());
        LOGGER.info("keepAliveTimeout={}", protocol.getKeepAliveTimeout());
        LOGGER.info("connectionTimeout={}", protocol.getConnectionTimeout());
        LOGGER.info("compression={}", protocol.getCompression());
        LOGGER.info("compressionMimeTypes={}", protocol.getCompressibleMimeType());
    }
}
