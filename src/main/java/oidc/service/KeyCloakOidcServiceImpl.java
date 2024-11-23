package oidc.service;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import oidc.util.OidcUtil;
import okhttp3.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class KeyCloakOidcServiceImpl implements OidcService {
    @Value("${keyclock.oidc.auth.code.endpoint}")
    private String authorizationEndpoint;

    @Value("${keycloak.oidc.auth.token.endpoint}")
    private String tokenEndpoint;

    @Value("${keyclock.oidc.auth.response_type}")
    private String responseType;

    @Value("${keyclock.oidc.auth.redirect_uri}")
    private String redirectUri;

    @Value("${keyclock.oidc.auth.client_id}")
    private String clientId;

    @Value("${keyclock.oidc.auth.client_secret}")
    private String clientSecret;

    @Value("${keyclock.oidc.auth.scope}")
    private String scope;

    @Value("${keycloak.oidc.auth.grant_type}")
    private String grantType;

    @Value("${keycloak.oidc.auth.introspect.endpoint}")
    private String introspectEndpoint;

    private static final MediaType X_WWW_FORM_URLENCODED = MediaType.parse("application/x-www-form-urlencoded");

    @Override
    public void redirectIfLoginRequired(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        if (isLoginRequired(request)) {
            // Redirect to our authorization endpoint to begin the login process
            final String redirectUrl = createRedirectUrl(request);

            System.out.println("=== User is not logged in, redirecting: " + redirectUrl);

            response.sendRedirect(redirectUrl);
        }
    }

    @Override
    public boolean isLoginRequired(final HttpServletRequest request) {
        // If the access token cannot be found in the session then we need to login
        final DecodedJWT accessToken = (DecodedJWT) request.getSession().getAttribute("access_token");

        return accessToken == null;
    }

    @Override
    public String exchangeCodeForTokens(final String authorizationCode) throws IOException {
        String token = null;

        final String basicAuthString = clientId + ":" + clientSecret;

        final String basicAuth = Base64.getEncoder().encodeToString(basicAuthString.getBytes(StandardCharsets.UTF_8));
        final RequestBody body = RequestBody.create(X_WWW_FORM_URLENCODED,
                String.format("grant_type=%s&code=%s&redirect_uri=%s&scope=%s",
                grantType, authorizationCode, redirectUri, scope));

        // Don't ever do this in production because it allows any certificate!
        final OkHttpClient client = OidcUtil.getUnsafeOkHttpClient();
        final Request request = new Request.Builder()
                .url(tokenEndpoint)
                .post(body)
                .addHeader("Authorization", "Basic " + basicAuth)
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .build();

        final Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            token = response.body().string();
        }

        return token;

    }

    @Override
    public String introspect(String accessToken) throws IOException {
        String user = null;

        final String basicAuthString = clientId + ":" + clientSecret;

        final String basicAuth = Base64.getEncoder().encodeToString(basicAuthString.getBytes(StandardCharsets.UTF_8));
        final RequestBody body = RequestBody.create(X_WWW_FORM_URLENCODED,
                String.format("token=%s", accessToken));

        // Don't ever do this in production because it allows any certificate!
        final OkHttpClient client = OidcUtil.getUnsafeOkHttpClient();
        final Request request = new Request.Builder()
                .url(introspectEndpoint)
                .post(body)
                .addHeader("Authorization", "Basic " + basicAuth)
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .build();

        final Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            user = response.body().string();
        }

        return user;


    }

    private String createRedirectUrl(final HttpServletRequest request) throws MalformedURLException {
        final String queryString = request.getQueryString();
        final String requestUrl = request.getRequestURL().toString();
        final URL url = new URL(requestUrl);

        final String nonce = OidcUtil.generateRandomString(32);
        final String state = url.getPath() + (queryString == null ? "" : "?" + queryString);

        final String redirectUrl = String.format(
                "%s?response_type=%s&redirect_uri=%s&state=%s&nonce=%s&client_id=%s&scope=%s",
                authorizationEndpoint,
                responseType,
                redirectUri,
                state,
                nonce,
                clientId,
                scope);
        System.out.println("Token end point = "+redirectUrl);

        return redirectUrl;
    }
}
