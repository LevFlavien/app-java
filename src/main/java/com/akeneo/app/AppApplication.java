package com.akeneo.app;

import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.stream.JsonParser;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.tomcat.util.buf.HexUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class AppApplication {
    static final String OAUTH_CLIENT_ID = "cb79c98a-4856-427a-98f9-80d803a8bbfe";
    static final String OAUTH_CLIENT_SECRET = "ZWIyYzQxOTBjNmM4ZGU1Y2FhNzAzOTNhOWQ4ODM2NWY2ZDE5OWRiMjk3NDZlZjhiMDIyZDIzZjRhYzU5NTIwNA";
    static final String OAUTH_SCOPES = "read_products write_products";

    @GetMapping("/activate")
    public void activate(HttpServletRequest request, HttpSession session, HttpServletResponse response) throws Exception {
        // Create a random state for preventing cross-site request forgery
        byte[] randomBytes = new byte[10];
        new SecureRandom().nextBytes(randomBytes);
        String state = HexUtils.toHexString(randomBytes);

        Object pimUrl = request.getParameter("pim_url");
        if (pimUrl == null) {
            throw new Exception("Missing PIM URL in the query");
        }

        // Store in the user session the state and the PIM URL
        session.setAttribute("oauth2_state", state);
        session.setAttribute("pim_url", pimUrl.toString());

        // Build url for the Authorization Request
        // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
        String authorizeUrl = pimUrl + "/connect/apps/v1/authorize" + "?response_type=code" + "&client_id=" + OAUTH_CLIENT_ID
                + "&scope=" + OAUTH_SCOPES + "&state=" + state;

        // Redirect the user to the Authorization URL
        response.sendRedirect(authorizeUrl);
    }

    @GetMapping("/callback")
    public String callback(HttpServletRequest request, HttpSession session) throws Exception {
        Object sessionState = session.getAttribute("oauth2_state");
        String stateParam = request.getParameter("state");

        // We check if the received state is the same as in the session, for security.
        if (sessionState == null || !sessionState.equals(stateParam)) {
            throw new Exception("Invalid state");
        }

        Object code = request.getParameter("code");
        if (code == null) {
            throw new Exception("Missing authorization code");
        }

        Object pimUrl = session.getAttribute("pim_url");
        if (pimUrl == null) {
            throw new Exception("No PIM url in session");
        }

        // Generate code challenge
        byte[] randomBytes = new byte[30];
        new SecureRandom().nextBytes(randomBytes);
        String codeIdentifier = HexUtils.toHexString(randomBytes);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] codeChallengeBytes = digest.digest((codeIdentifier + OAUTH_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        String codeChallenge = HexUtils.toHexString(codeChallengeBytes);

        String accessTokenUrl = pimUrl + "/connect/apps/v1/oauth2/token";

        JsonObject json = Json.createObjectBuilder()
                .add("client_id", OAUTH_CLIENT_ID)
                .add("code_identifier", codeIdentifier)
                .add("code_challenge", codeChallenge)
                .add("code", code.toString())
                .add("grant_type", "authorization_code")
                .build();

        // Do a POST request on the token endpoint
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest authorizeRequest = HttpRequest.newBuilder()
                .uri(URI.create(accessTokenUrl))
                .header("Content-Type", "application/json")
                .POST(BodyPublishers.ofString(json.toString()))
                .build();

        HttpResponse<String> response = client.send(authorizeRequest, BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            // Handle error
        }

        return response.body();
    }

    public static void main(String[] args) {
        SpringApplication.run(AppApplication.class, args);
    }
}
