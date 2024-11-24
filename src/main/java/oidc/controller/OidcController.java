package oidc.controller;

import com.auth0.jwt.JWT;
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
     * A page to display the refresh details.
     *
     * @param request  the request object.
     * @param response the response object.
     * @param model    the model to be passed to the view.
     * @return         a string indicating which view to display.
     */
    @GetMapping(value="/refresh")
    private String refresh(final HttpServletRequest request, final HttpServletResponse response, final Model model)
            throws IOException {
        System.out.println("===> /introspect route");

        oidcService.redirectIfLoginRequired(request, response);

        model.addAttribute("refresh_token", request.getSession().getAttribute("refresh_token"));

        return "refresh";
    }

    @GetMapping("/callback")
    public String callback(final HttpServletRequest request, @RequestParam("code") String authCode, @RequestParam("state") String state, HttpSession session) throws IOException {
        // Verify the state and nonce
        // verification logics

        String redirectUrl = "/";
        final String rawToken = oidcService.exchangeCodeForTokens(authCode);

        // Parse the token
        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode token = mapper.readTree(rawToken);

        final JsonNode accessToken = token.get("access_token");
        final JsonNode idToken = token.get("id_token");
        final JsonNode refreshToken = token.get("refresh_token");

        System.out.println();
        System.out.println("=== Access Token: " + accessToken.textValue());
        System.out.println();
        System.out.println("=== ID Token: " + idToken.textValue());

        final DecodedJWT accessJwt = JWT.decode(accessToken.asText());
        final DecodedJWT idJwt = JWT.decode(idToken.asText());

        request.getSession().setAttribute("authcode", authCode);
        request.getSession().setAttribute("access_token", accessJwt);
        request.getSession().setAttribute("id_token", idJwt);
        request.getSession().setAttribute("refresh_token", refreshToken.textValue());

        // Extract user information
        String subject = idJwt.getClaim("sub").asString();
        String name = idJwt.getClaim("name").asString();
        String preferredUsername = idJwt.getClaim("preferred_username").asString();
        String email = idJwt.getClaim("email").asString();

        System.out.println("Subject: " + subject);
        System.out.println("Name: " + name);
        System.out.println("Preferred Username: " + preferredUsername);
        System.out.println("Email: " + email);

        /*
        //introspect
        final String rawUser = oidcService.introspect(accessJwt.getToken());
        final JsonNode user = mapper.readTree(rawUser);

        final JsonNode name = user.get("name");
        final JsonNode email = user.get("email");
        final JsonNode username = user.get("username");
        final JsonNode status = user.get("active");

        request.getSession().setAttribute("name", name.textValue());
        request.getSession().setAttribute("email", email.textValue());
        request.getSession().setAttribute("username", username.textValue());
        request.getSession().setAttribute("status", status.asBoolean() ? "Active" : "Inactive");
        */

        if (!state.isEmpty()) {
            // We have a state, redirect there
            redirectUrl = state;
        }

        return "redirect:" + redirectUrl;
    }

}
