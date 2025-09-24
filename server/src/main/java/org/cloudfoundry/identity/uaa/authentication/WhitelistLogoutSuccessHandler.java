package org.cloudfoundry.identity.uaa.authentication;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwt.ChainedSignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.SignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.oauth.beans.LegacyRedirectResolver;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA.buildIdTokenValidator;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.findMatchingRedirectUri;

@Slf4j
@Setter
public final class WhitelistLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
    private static final String OPEN_ID_TOKEN_HINT = "id_token_hint";

    private List<String> whitelist;

    @Getter
    private MultitenantClientServices clientDetailsService;
    private KeyInfoService keyInfoService;

    private RedirectResolver redirectResolver;


    public WhitelistLogoutSuccessHandler(List<String> whitelist) {
        this.whitelist = whitelist;
        this.redirectResolver = new LegacyRedirectResolver();
    }

    @Override
    protected boolean isAlwaysUseDefaultTargetUrl() {
        return false;
    }

    private Set<String> getClientWhitelist(ClientDetails client) {
        if(client != null) {
            return client.getRegisteredRedirectUri();
        }
        return null;
    }

    private ClientDetails getClient(HttpServletRequest request) {
        String clientId = null;
        ClientDetails client = null;
        String idToken = request.getParameter(OPEN_ID_TOKEN_HINT);

        if (idToken != null) {
            try {
                Map<String, KeyInfo> keys = keyInfoService.getKeys();
                List<SignatureVerifier> signatureVerifiers = keys.values().stream().map(KeyInfo::getVerifier).toList();
                JwtTokenSignedByThisUAA jwtToken = buildIdTokenValidator(idToken, new ChainedSignatureVerifier(signatureVerifiers), keyInfoService);
                clientId = (String) jwtToken.getClaims().get(ClaimConstants.AZP);
            } catch (InvalidTokenException e) {
                log.debug("Invalid token (could not verify signature)");
            }
        } else {
            clientId = request.getParameter(CLIENT_ID);
        }

        if (StringUtils.hasText(clientId)) {
            try {
                client = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
            } catch (NoSuchClientException x) {
                log.debug("Unable to find client with ID:%s for logout redirect".formatted(clientId));
            }
        }
        return client;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        String targetUrl = request.getParameter("post_logout_redirect_uri");

        if (targetUrl == null) {
            targetUrl = super.determineTargetUrl(request, response);
        }

        if (isInternalRedirect(targetUrl, request)) {
            return targetUrl;
        }

        String defaultTargetUrl = getDefaultTargetUrl();
        if (targetUrl.equals(defaultTargetUrl)) {
            return targetUrl;
        }
        ClientDetails client = getClient(request);
        String whiteListRedirect;
        try{
            whiteListRedirect = redirectResolver.resolveRedirect(targetUrl, client);
        } catch (OAuth2Exception | NullPointerException e){
            logger.info(e.getMessage());
            whiteListRedirect = findMatchingRedirectUri(whitelist, targetUrl, defaultTargetUrl);
        }

        //TODO: check this
/*        Set<String> clientWhitelist = getClientWhitelist(request);
        Set<String> combinedWhitelist = Stream.of(
                Optional.ofNullable(whitelist).orElse(List.of()),
                Optional.ofNullable(clientWhitelist).orElse(Set.of()))
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());

        return findMatchingRedirectUri(combinedWhitelist, targetUrl, defaultTargetUrl);*/
        return whiteListRedirect;
    }

    private boolean isInternalRedirect(String targetUrl, HttpServletRequest request) {
        String serverUrl = request.getRequestURL().toString().replaceAll("/logout\\.do$", "/");
        return targetUrl.startsWith(serverUrl);
    }
}
