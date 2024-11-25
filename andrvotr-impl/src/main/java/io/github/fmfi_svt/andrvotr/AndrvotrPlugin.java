package io.github.fmfi_svt.andrvotr;

import java.io.IOException;
import net.shibboleth.idp.plugin.PluginException;
import net.shibboleth.idp.plugin.PropertyDrivenIdPPlugin;

public class AndrvotrPlugin extends PropertyDrivenIdPPlugin {
    public AndrvotrPlugin() throws IOException, PluginException {
        super(AndrvotrPlugin.class);
    }
}
