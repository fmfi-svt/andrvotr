package io.github.fmfi_svt.andrvotr.impl;

import java.io.IOException;
import javax.annotation.Nonnull;

import net.shibboleth.idp.plugin.IdPPlugin;
import net.shibboleth.idp.plugin.PropertyDrivenIdPPlugin;
import net.shibboleth.profile.plugin.PluginException;

/**
 * Plugin description about the webauthn plugin.
 */
public class ExamplePlugin extends PropertyDrivenIdPPlugin {

    /**
     * Constructor.
     *
     * @param claz type of plugin
     * 
     * @throws IOException if properties can't be loaded
     * @throws PluginException if another error occurs
     */
    public ExamplePlugin() throws IOException, PluginException {
        super(ExamplePlugin.class);
    }

}
