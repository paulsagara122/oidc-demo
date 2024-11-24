package oidc.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import oidc.service.OidcService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
public class OidcController {

    @Autowired
    OidcService oidcService;

    /**
     * Home page.
     *
     * @param request  the request object.
     * @param response the response object.
     * @param model    the model to be passed to the view.
     * @return         a string indicating which view to display.
     */
    @GetMapping("/")
    public String home(final HttpServletRequest request, final HttpServletResponse response, final Model model) throws IOException {
        model.addAttribute("message", "Welcome to OIDC Demo App.");
        System.out.println("===> Home Page!");

        oidcService.redirectIfLoginRequired(request, response);

        //add user details to home page
        if (request.getSession() != null) {
            final DecodedJWT idJwt = (DecodedJWT) request.getSession().getAttribute("id_token");
            if (idJwt != null) {
                model.addAttribute("username", idJwt.getClaim("preferred_username").asString());
            }
        }
        return "index";
    }


    /**
     * A page to display the token details.
     *
     * @param request  the request object.
     * @param response the response object.
     * @param model    the model to be passed to the view.
     * @return         a string indicating which view to display.
     */
    @GetMapping(value="/introspect")
    private String introspect(final HttpServletRequest request, final HttpServletResponse response, final Model model)
            throws IOException {
        System.out.println("===> /introspect route");

        oidcService.redirectIfLoginRequired(request, response);

        if (request.getSession() != null) {
            final DecodedJWT accessTokenJwt = (DecodedJWT) request.getSession().getAttribute("access_token");

            final ObjectMapper mapper = new ObjectMapper();
            final String rawTokenDetails = oidcService.introspect(accessTokenJwt.getToken());
            final JsonNode tokenDetails = mapper.readTree(rawTokenDetails);

            System.out.println();
            System.out.println("===> sid:"+tokenDetails.get("sid"));
            System.out.println();
            System.out.println("===> sub:"+tokenDetails.get("sub"));
            model.addAttribute("sid", tokenDetails.get("sid").textValue());
            model.addAttribute("sub", tokenDetails.get("sub").textValue());

        }

        return "introspect";
    }

    @GetMapping("/callback")
    public String callback(final HttpServletRequest request, @RequestParam("code") String authCode, @RequestParam("state") String state, HttpSession session) throws IOException {

        System.out.println("===> /callback route");

        // Verify the state and nonce
        // verification logics
        // ...

        String redirectUrl = "/";
        final String rawToken = oidcService.exchangeCodeForTokens(authCode);
        oidcService.saveTokenToSession(request, rawToken);

        if (!state.isEmpty()) {
            // We have a state, redirect there
            redirectUrl = state;
        }

        return "redirect:" + redirectUrl;
    }

}
