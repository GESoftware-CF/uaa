package org.cloudfoundry.identity.uaa;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.support.StandardServletEnvironment;

import jakarta.servlet.FilterRegistration;
import jakarta.servlet.MultipartConfigElement;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRegistration;
import java.util.EventListener;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UaaWebApplicationInitializerTest {

    private static final String TEST_MAX_UPLOAD_BYTES = "5242880";

    private UaaWebApplicationInitializer initializer;
    private ConfigurableWebApplicationContext context;
    private StandardServletEnvironment environment;
    private ServletContext servletContext;

    private FilterRegistration.Dynamic filterRegistration;

    private ServletRegistration.Dynamic servletRegistration;


    @BeforeEach
    void setup() {
        // Subclass overrides getEnvVar() so no real env var is required during tests
        initializer = new UaaWebApplicationInitializer() {
            @Override
            String getEnvVar(String name) {
                if ("BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES".equals(name)) {
                    return TEST_MAX_UPLOAD_BYTES;
                }
                return System.getenv(name);
            }
        };
        context = mock(ConfigurableWebApplicationContext.class);
        environment = new StandardServletEnvironment();
        servletContext = mock(ServletContext.class);


        when(context.getServletContext()).thenReturn(servletContext);
        when(context.getEnvironment()).thenReturn(environment);
        Mockito.doAnswer((Answer<Void>) invocation -> {
            System.err.println(invocation.getArguments()[0]);
            return null;
        }).when(servletContext).log(anyString());
        when(servletContext.getContextPath()).thenReturn("/context");

        filterRegistration = mock(FilterRegistration.Dynamic.class);
        when(servletContext.addFilter(anyString(), ArgumentMatchers.any(jakarta.servlet.Filter.class)))
                .thenReturn(filterRegistration);

        servletRegistration = mock(ServletRegistration.Dynamic.class);
        when(servletContext.addServlet(anyString(), ArgumentMatchers.any(jakarta.servlet.Servlet.class)))
                .thenReturn(servletRegistration);

    }

    @Test
    void testServletContextListeners() throws ServletException {
        initializer.onStartup(servletContext);

        ArgumentCaptor<EventListener> listenerArgumentCaptor = ArgumentCaptor.forClass(EventListener.class);
        verify(servletContext, atLeastOnce()).addListener(listenerArgumentCaptor.capture());
        List<EventListener> listeners = listenerArgumentCaptor.getAllValues();
        assertThat(listeners).isNotNull();
        assertThat(listeners.size()).isEqualTo(2);
        assertThat(listeners.getFirst()).isInstanceOf(HttpSessionEventPublisher.class);
        assertThat(listeners.get(1)).isInstanceOf(ContextLoaderListener.class);
    }

    @Test
    void shouldConfigureMultipartWithMaxFileSizeFromEnvVar() throws ServletException {
        initializer.onStartup(servletContext);

        ArgumentCaptor<MultipartConfigElement> multipartCaptor =
                ArgumentCaptor.forClass(MultipartConfigElement.class);
        verify(servletRegistration).setMultipartConfig(multipartCaptor.capture());

        MultipartConfigElement config = multipartCaptor.getValue();
        assertThat(config.getMaxFileSize()).isEqualTo(Long.parseLong(TEST_MAX_UPLOAD_BYTES));
        assertThat(config.getMaxRequestSize()).isEqualTo(Long.parseLong(TEST_MAX_UPLOAD_BYTES));
        assertThat(config.getFileSizeThreshold()).isZero();
    }

}