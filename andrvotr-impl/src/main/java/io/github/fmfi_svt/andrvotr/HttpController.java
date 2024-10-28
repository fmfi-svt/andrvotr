package io.github.fmfi_svt.andrvotr;

import java.io.IOException;
import java.io.PrintWriter;

import javax.annotation.Nonnull;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.shibboleth.shared.component.AbstractInitializableComponent;

@Controller
@RequestMapping("/andrvotr")
public final class HttpController extends AbstractInitializableComponent {

    public HttpController() {
        System.err.println("XXXXXXX HttpController is initializing!");
    }

    @PostMapping("/fabricate")
    public void fabricate(@Nonnull final HttpServletRequest httpRequest, @Nonnull final HttpServletResponse httpResponse) throws IOException {
        httpResponse.setContentType("text/plain; charset=UTF-8");
        PrintWriter writer = httpResponse.getWriter();
        writer.println("Hello from andrvotr fabricate!!!");
        writer.close();
    }

}
