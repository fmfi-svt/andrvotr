package io.github.fmfi_svt.andrvotr;

import java.io.IOException;
import net.shibboleth.idp.plugin.PropertyDrivenIdPPlugin;
import net.shibboleth.profile.plugin.PluginException;

public class AndrvotrPlugin extends PropertyDrivenIdPPlugin {
    public AndrvotrPlugin() throws IOException, PluginException {
        super(AndrvotrPlugin.class);
    }
}
