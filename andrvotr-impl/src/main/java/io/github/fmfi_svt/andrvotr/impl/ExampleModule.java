package io.github.fmfi_svt.andrvotr.impl;

import java.io.IOException;

import net.shibboleth.idp.module.IdPModule;
import net.shibboleth.idp.module.PropertyDrivenIdPModule;
import net.shibboleth.profile.module.ModuleException;

/**
 * {@link IdPModule IdP Module} implementation.
 */
public class ExampleModule extends PropertyDrivenIdPModule{
    
    /**
     * Constructor.
     *  
     * @throws ModuleException on error
     * @throws IOException on error
     */
    public ExampleModule() throws IOException, ModuleException {
        super(ExampleModule.class);
    }
    
}
