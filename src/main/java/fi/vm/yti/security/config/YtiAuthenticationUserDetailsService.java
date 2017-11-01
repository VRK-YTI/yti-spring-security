package fi.vm.yti.security.config;

import fi.vm.yti.security.Role;
import fi.vm.yti.security.ShibbolethAuthenticationDetails;
import fi.vm.yti.security.YtiUser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.util.StringUtils.isEmpty;

public class YtiAuthenticationUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private static final Log log = LogFactory.getLog(YtiAuthenticationUserDetailsService.class);

    private final RestTemplate restTemplate;
    private final String groupmanagementUrl;

    YtiAuthenticationUserDetailsService(String groupmanagementUrl) {
        this.groupmanagementUrl = groupmanagementUrl;
        this.restTemplate = new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient()));
    }

    private static HttpClient httpClient() {

        TrustStrategy naivelyAcceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;

        try {
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(null, naivelyAcceptingTrustStrategy)
                    .build();

            return HttpClients.custom()
                    .setSSLSocketFactory(new SSLConnectionSocketFactory(sslContext))
                    .build();

        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {
        ShibbolethAuthenticationDetails shibbolethDetails = (ShibbolethAuthenticationDetails) token.getDetails();

        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(this.groupmanagementUrl)
                .path("/public-api/user")
                .queryParam("email", shibbolethDetails.getEmail());

        if (!isEmpty(shibbolethDetails.getFirstName()) && !isEmpty(shibbolethDetails.getLastName())) {
            uriBuilder.queryParam("firstName", shibbolethDetails.getFirstName());
            uriBuilder.queryParam("lastName", shibbolethDetails.getLastName());
        }

        String getUserUri = uriBuilder.build().toUriString();

        User user = this.restTemplate.getForObject(getUserUri, User.class);

        Map<UUID, Set<Role>> rolesInOrganizations = new HashMap<>();

        for (Organization organization : user.organization) {

            Set<Role> roles = organization.role.stream()
                    .filter(YtiAuthenticationUserDetailsService::isRoleMappableToEnum)
                    .map(Role::valueOf)
                    .collect(Collectors.toSet());

            rolesInOrganizations.put(organization.uuid, roles);
        }

        return new YtiUser(user.email, user.firstName, user.lastName, user.superuser, user.newlyCreated, rolesInOrganizations);
    }

    private static boolean isRoleMappableToEnum(String roleString) {

        boolean contains = Role.contains(roleString);

        if (!contains) {
            log.warn("Cannot map role (" + roleString + ")" + " to role enum");
        }

        return contains;
    }
}

class User {

    public String email;
    public String firstName;
    public String lastName;
    public boolean superuser;
    public boolean newlyCreated;
    public List<Organization> organization;
}

class Organization {

    public UUID uuid;
    public List<String> role;
}
