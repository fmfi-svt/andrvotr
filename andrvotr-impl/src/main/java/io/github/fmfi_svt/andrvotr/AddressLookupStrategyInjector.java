package io.github.fmfi_svt.andrvotr;

import net.shibboleth.shared.component.AbstractInitializableComponent;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;

/// Registers `AddressLookupStrategy` as the "shibboleth.SessionAddressLookupStrategy" bean.
///
/// The bean is documented at https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199506072/SessionConfiguration,
/// though barely. It has no built-in definition - it is is intended as an optional extension point for administrators.
/// In the unlikely event an administrator defines their own "shibboleth.SessionAddressLookupStrategy" in their
/// configuration, this postprocessor renames it to another id and chains it after our implementation.
public final class AddressLookupStrategyInjector extends AbstractInitializableComponent
        implements BeanDefinitionRegistryPostProcessor {
    private static final String TARGET_BEAN_ID = "shibboleth.SessionAddressLookupStrategy";
    private static final String RENAMED_BEAN_ID = "andrvotr.original.shibboleth.SessionAddressLookupStrategy";

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
        // Sadly no logging, because this class apparently runs too early for logging to work.

        boolean exists = registry.containsBeanDefinition(TARGET_BEAN_ID);

        if (exists) {
            BeanDefinition originalDefinition = registry.getBeanDefinition(TARGET_BEAN_ID);
            registry.removeBeanDefinition(TARGET_BEAN_ID);
            registry.registerBeanDefinition(RENAMED_BEAN_ID, originalDefinition);
        }

        BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(AddressLookupStrategy.class);
        if (exists) {
            builder.addConstructorArgReference(RENAMED_BEAN_ID);
        } else {
            builder.addConstructorArgValue(null);
        }
        registry.registerBeanDefinition(TARGET_BEAN_ID, builder.getBeanDefinition());
    }

    /// postProcessBeanFactory defaults to an empty method in Spring 6.1.0+, but our Spring is too old.
    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {}
}
