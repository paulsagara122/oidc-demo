package oidc.service;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface OidcService {

    /**
     * Sends a redirect if the user needs to login.
     *
     * @param request      the request object.
     * @param response     the response object.
     * @throws IOException Signals that an I/O exception of some sort has occurred.
     */
    public void redirectIfLoginRequired(HttpServletRequest request, HttpServletResponse response) throws IOException;

    /**
     * Determines if a user needs to login.
     *
     * @param request the request object.
     * @return        returns a boolean indicating that the user needs to login.
     */
    public boolean isLoginRequired(HttpServletRequest request);


    /**
     * Exchange the authentication code for an OpenID Connect token.
     *
     * @param authorizationCode         the authentication code returned by the server.
     * @return                          returns a string of the entire set of tokens.
     * @throws IOException              Signals that an I/O exception of some sort has occurred.
     */
    public String exchangeCodeForTokens(String authorizationCode) throws IOException;


    /**
     * Exchange the authentication code for an OpenID Connect token.
     *
     * @param accessToken         the access token returned by the server.
     * @return                          returns a string of the entire set of user.
     * @throws IOException              Signals that an I/O exception of some sort has occurred.
     */
    public String introspect(String accessToken) throws IOException;
}
