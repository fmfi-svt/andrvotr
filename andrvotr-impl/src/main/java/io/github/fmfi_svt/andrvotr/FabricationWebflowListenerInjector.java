package io.github.fmfi_svt.andrvotr;

import java.util.Map;
import javax.annotation.Nonnull;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.primitive.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;

/// Injects our custom listener to webflow-config.xml.
///
/// java-identity-provider/idp-conf-impl/src/main/resources/net/shibboleth/idp/conf/webflow-config.xml
/// contains the following definition:
///
///     <webflow:flow-executor id="flowExecutor">
///         <webflow:flow-execution-repository max-execution-snapshots="0" conversation-manager="conversationManager" />
///         <webflow:flow-execution-listeners>
///             <webflow:listener ref="profileRequestContextFlowExecutionListener"
///                               criteria="%{idp.profile.exposeProfileRequestContextInServletRequest:*}" />
///             <webflow:listener ref="csrfTokenFlowExecutionListener"/>
///         </webflow:flow-execution-listeners>
///     </webflow:flow-executor>
///
/// Our goal is to inject another listener:
///
///     <webflow:listener ref="andrvotrFabricationWebflowListener" criteria="SAML2/Redirect/SSO" />
public final class FabricationWebflowListenerInjector extends AbstractInitializableComponent
        implements BeanFactoryPostProcessor {

    private static final String LISTENER_BEAN_REF = "andrvotrFabricationWebflowListener";

    /// Comma-separated list of flow IDs (defined in webflow-config.xml) where our listener should run.
    private static final String CRITERIA = "SAML2/Redirect/SSO";

    private final @Nonnull Logger log = LoggerFactory.getLogger(FabricationWebflowListenerInjector.class);

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
        log.info("Adding {} to flowExecutor", LISTENER_BEAN_REF);

        // This code relies on a few internal implementation details of Spring Webflow which could break in the future.
        // Unfortunately, BeanFactoryPostProcessor does not operate on the original XML tree with `<webflow:...>` tags,
        // but on parsed bean definitions. That means we must make several assumptions about the translation process:
        //
        // - org.springframework.webflow.config.FlowExecutorBeanDefinitionParser.addFlowExecutionListenerLoader() adds a
        //   property named "flowExecutionListenerLoader" whose value is a `BeanDefinition`.
        // - org.springframework.webflow.config.FlowExecutionListenerLoaderBeanDefinitionParser.doParse() adds a
        //   property named "listeners" whose value is a `Map<RuntimeBeanReference, String>`.
        //
        // If needed, the latest versions are here:
        // https://github.com/spring-projects/spring-webflow/blob/main/spring-webflow/src/main/java/org/springframework/webflow/config/FlowExecutorBeanDefinitionParser.java
        // https://github.com/spring-projects/spring-webflow/blob/main/spring-webflow/src/main/java/org/springframework/webflow/config/FlowExecutionListenerLoaderBeanDefinitionParser.java

        BeanDefinition flowExecutor = beanFactory.getBeanDefinition("flowExecutor");
        BeanDefinition listenerLoader =
                (BeanDefinition) flowExecutor.getPropertyValues().get("flowExecutionListenerLoader");
        @SuppressWarnings("unchecked")
        Map<RuntimeBeanReference, String> listeners = (Map<RuntimeBeanReference, String>)
                listenerLoader.getPropertyValues().get("listeners");
        log.debug("Listeners before: {}", listeners);
        listeners.put(new RuntimeBeanReference(LISTENER_BEAN_REF), CRITERIA);
        log.debug("Listeners after: {}", listeners);
    }
}
