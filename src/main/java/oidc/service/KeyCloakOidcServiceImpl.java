package oidc.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import oidc.util.OidcUtil;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
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

    @Value("${keycloak.oidc.auth.introspect.endpoint}")
    private String introspectEndpoint;

    private static final MediaType X_WWW_FORM_URLENCODED = MediaType.parse("application/x-www-form-urlencoded");

    final private static String ACCESS_TOKEN_GRANT_TYPE = "authorization_code";

    final private static String REFRESH_TOKEN_GRANT_TYPE = "refresh_token";

    @Override
    public void redirectIfLoginRequired(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        if (isLoginRequired(request)) {
            // Redirect to our authorization endpoint to begin the login process
            final String redirectUrl = createRedirectUrl(request);

            System.out.println("=== User is not logged in, redirecting: " + redirectUrl);

            response.sendRedirect(redirectUrl);
        } else {
            refreshAccessTokenIfNeeded(request, response);
        }
    }

    @Override
    public void refreshAccessTokenIfNeeded(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final DecodedJWT accessTokenJwt = (DecodedJWT) request.getSession().getAttribute("access_token");
        if (accessTokenJwt != null) {
            long expiresAt = accessTokenJwt.getClaim("exp").asInt();
            // Convert to milliseconds
            long expiresAtMillis = expiresAt * 1000L;
            long currTime = System.currentTimeMillis();
            if (currTime >= expiresAtMillis) {
                System.out.println("===> Token expired! Need a new token.");
                final DecodedJWT refreshTokenJwt = (DecodedJWT) request.getSession().getAttribute("refresh_token");
                String token = refreshAccessToken(refreshTokenJwt.getToken());
                saveTokenToSession(request, token);
            }
        }
    }

    private String refreshAccessToken(final String refreshToken) throws IOException {
        String token = null;

        final String basicAuthString = clientId + ":" + clientSecret;

        final String basicAuth = Base64.getEncoder().encodeToString(basicAuthString.getBytes(StandardCharsets.UTF_8));
        final RequestBody body = RequestBody.create(X_WWW_FORM_URLENCODED,
                String.format("grant_type=%s&refresh_token=%s",
                        REFRESH_TOKEN_GRANT_TYPE, refreshToken));

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
                        ACCESS_TOKEN_GRANT_TYPE, authorizationCode, redirectUri, scope));

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

    @Override
    public void saveTokenToSession(final HttpServletRequest request, final String token) throws JsonProcessingException {
        // Parse the token
        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode jsonToken = mapper.readTree(token);

        final JsonNode accessToken = jsonToken.get("access_token");
        final JsonNode idToken = jsonToken.get("id_token");
        final JsonNode refreshToken = jsonToken.get("refresh_token");

        System.out.println();
        System.out.println("=== Access Token: " + accessToken.textValue());
        System.out.println();
        System.out.println("=== ID Token: " + idToken.textValue());

        final DecodedJWT accessJwt = JWT.decode(accessToken.asText());
        final DecodedJWT idJwt = JWT.decode(idToken.asText());
        final DecodedJWT refreshJwt = JWT.decode(refreshToken.asText());

        request.getSession().setAttribute("access_token", accessJwt);
        request.getSession().setAttribute("id_token", idJwt);
        request.getSession().setAttribute("refresh_token", refreshJwt);

        // Extract user information
        String subject = idJwt.getClaim("sub").asString();
        String name = idJwt.getClaim("name").asString();
        String preferredUsername = idJwt.getClaim("preferred_username").asString();
        String email = idJwt.getClaim("email").asString();

        System.out.println("Subject: " + subject);
        System.out.println("Name: " + name);
        System.out.println("Preferred Username: " + preferredUsername);
        System.out.println("Email: " + email);

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
