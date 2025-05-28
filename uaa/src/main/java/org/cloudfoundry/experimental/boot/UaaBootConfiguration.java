package org.cloudfoundry.experimental.boot;

import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.ApplicationContextFacade;
import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.ErrorPage;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import java.lang.reflect.Field;

import static org.springframework.util.ReflectionUtils.findField;
import static org.springframework.util.ReflectionUtils.getField;

@Configuration
public class UaaBootConfiguration implements ServletContextInitializer, WebMvcConfigurer {

    //TODO - This is currently a workaround to find static content
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        String base = System.getProperty("uaa.boot.webapp.dir");
        registry.addResourceHandler("/**")
                .addResourceLocations("file://"+base+"/");
    }

    @Bean
    WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> enableDefaultServlet() {
        return (factory) -> factory.setRegisterDefaultServlet(true);
    }

    @Bean
    DelegatingFilterProxyRegistrationBean springSessionRepositoryFilterRegistration() {
        return new DelegatingFilterProxyRegistrationBean(
                "springSessionRepositoryFilter"
        );
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        HttpSessionEventPublisher publisher = new HttpSessionEventPublisher();
        servletContext.addListener(publisher);

        //<error-page> from web.xml
        if (servletContext instanceof ApplicationContextFacade) {
            Field field = findField(ApplicationContextFacade.class, "context", ApplicationContext.class);
            field.setAccessible(true);
            ApplicationContext applicationContext = (ApplicationContext) getField(field, servletContext);

            field = findField(ApplicationContext.class, "context", StandardContext.class);
            field.setAccessible(true);
            StandardContext standardContext = (StandardContext) getField(field, applicationContext);

            ErrorPage error500 = new ErrorPage();
            error500.setErrorCode(500);
            error500.setLocation("/error500");
            standardContext.addErrorPage(error500);

            ErrorPage error404 = new ErrorPage();
            error404.setErrorCode(404);
            error404.setLocation("/error404");
            standardContext.addErrorPage(error404);

            ErrorPage error429 = new ErrorPage();
            error429.setErrorCode(429);
            error429.setLocation("/error429");
            standardContext.addErrorPage(error429);

            ErrorPage error = new ErrorPage();
            error.setLocation("/error");
            standardContext.addErrorPage(error);

            ErrorPage errorEx = new ErrorPage();
            errorEx.setLocation("/rejected");
            errorEx.setExceptionType("org.springframework.security.web.firewall.RequestRejectedException");
            standardContext.addErrorPage(errorEx);
        }
    }
}
