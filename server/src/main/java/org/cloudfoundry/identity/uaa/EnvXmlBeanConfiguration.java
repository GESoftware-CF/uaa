package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.impl.config.EnvironmentPropertiesFactoryBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.env.Environment;

import java.io.IOException;

@Configuration
public class EnvXmlBeanConfiguration {

    @Bean
    // <bean id="applicationProperties" class="org.springframework.beans.factory.config.PropertiesFactoryBean">
    PropertiesFactoryBean applicationProperties(Environment environment) {
        PropertiesFactoryBean bean = new PropertiesFactoryBean();
        EnvironmentPropertiesFactoryBean envFactoryBean = new EnvironmentPropertiesFactoryBean();
        envFactoryBean.setEnvironment(environment);
        bean.setPropertiesArray(envFactoryBean.getObject());
        return bean;
    }

    @Bean
    // <context:property-placeholder properties-ref="applicationProperties"/>
    PropertySourcesPlaceholderConfigurer propertyPlaceHolder(
            @Qualifier("applicationProperties") PropertiesFactoryBean applicationProperties
    ) throws IOException {
        PropertySourcesPlaceholderConfigurer bean = new PropertySourcesPlaceholderConfigurer();
        bean.setIgnoreUnresolvablePlaceholders(false);
        bean.setProperties(applicationProperties.getObject());
        return bean;
    }
//
//    @Bean
//    EnvironmentMapFactoryBean config() {
//        return new EnvironmentMapFactoryBean();
//    }
//
//    @Bean
//    @Role(2) //ROLE_INFRASTRUCTURE
//    // <context:mbean-server id="mbeanServer"/>
//    MBeanServerFactoryBean mbeanServer() {
//        MBeanServerFactoryBean bean = new MBeanServerFactoryBean();
//        bean.setLocateExistingServerIfPossible(true);
//        return bean;
//    }
//
//    @Bean
//    // <context:mbean-export server="mbeanServer" default-domain="spring.application" registration="replaceExisting"/>
//    AnnotationMBeanExporter mBeanExporter1(MBeanServerFactoryBean mbeanServer) {
//        AnnotationMBeanExporter bean = new AnnotationMBeanExporter();
//        bean.setDefaultDomain("spring.application");
//        bean.setRegistrationPolicy(RegistrationPolicy.REPLACE_EXISTING);
//        bean.setServer(mbeanServer.getObject());
//        return bean;
//    }
//
//    @Bean
//    @Role(2) //ROLE_INFRASTRUCTURE
//    // <bean class="org.springframework.jmx.export.MBeanExporter">
//    MBeanExporter mbeanExporter(MBeanServerFactoryBean mbeanServer, @Qualifier("config") EnvironmentMapFactoryBean config) {
//        MBeanExporter bean = new MBeanExporter();
//        bean.setRegistrationPolicy(RegistrationPolicy.REPLACE_EXISTING);
//        bean.setServer(mbeanServer.getObject());
//        Map<String, Object> beans = new LinkedHashMap<>();
//        beans.put("spring.application:type=Config,name=uaa", config);
//        bean.setBeans(beans);
//        MethodNameBasedMBeanInfoAssembler assembler = new MethodNameBasedMBeanInfoAssembler();
//        Properties mappings = new Properties();
//        mappings.put("spring.application:type=Config,name=uaa", "getObject");
//        return bean;
//    }
}
