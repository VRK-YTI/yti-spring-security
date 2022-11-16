package fi.vm.yti.security.config;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jetbrains.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestAttributeAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import fi.vm.yti.security.AuthenticatedUserProvider;
import fi.vm.yti.security.AuthorizationException;
import fi.vm.yti.security.Role;
import fi.vm.yti.security.ShibbolethAuthenticationDetails;
import fi.vm.yti.security.YtiUser;
import fi.vm.yti.security.util.RoleUtil;
import static fi.vm.yti.security.config.RestTemplateConfig.httpClient;
import static java.util.Collections.emptyList;

@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityBaseConfig extends WebSecurityConfigurerAdapter {

    private final String groupmanagementUrl;
    private final boolean allowFakeUser;
    private final List<NewlyCreatedUserListener> newlyCreatedUserListeners;
    private final @Nullable FakeUserLoginProvider fakeUserLoginProvider;
    private final RestTemplate restTemplate;
    private static final String HEADER_YTITOKEN = "YTITOKEN";

    @Autowired
    SecurityBaseConfig(@Value("${groupmanagement.url}") final String groupmanagementUrl,
                       @Value("${fake.login.allowed:false}") final boolean allowFakeUser,
                       final Optional<List<NewlyCreatedUserListener>> newlyCreatedUserListeners,
                       final Optional<FakeUserLoginProvider> fakeUserLoginProvider) {

        this.groupmanagementUrl = groupmanagementUrl;
        this.allowFakeUser = fakeUserLoginProvider.isPresent() || allowFakeUser;
        this.newlyCreatedUserListeners = newlyCreatedUserListeners.orElse(emptyList());
        this.fakeUserLoginProvider = fakeUserLoginProvider.orElse(null);
        this.restTemplate = new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient()));
    }

    @Bean
    AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticatedUserDetailsService() {
        return new YtiAuthenticationUserDetailsService(groupmanagementUrl);
    }

    @Bean
    AuthenticationDetailsSource<HttpServletRequest, ShibbolethAuthenticationDetails> authenticationDetailsSource() {
        return ShibbolethAuthenticationDetails::new;
    }

    @Bean
    Filter authenticationFilter() throws Exception {

        final RequestAttributeAuthenticationFilter authenticationFilter = new RequestAttributeAuthenticationFilter() {
            @Override
            protected boolean principalChanged(final HttpServletRequest request,
                                               final Authentication currentAuthentication) {
                // need to update principal in any case since organizations might have changed
                return true;
            }
        };

        authenticationFilter.setPrincipalEnvironmentVariable("mail");
        authenticationFilter.setExceptionIfVariableMissing(false);
        authenticationFilter.setCheckForPrincipalChanges(true);
        authenticationFilter.setInvalidateSessionOnPrincipalChange(false);
        authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource());
        authenticationFilter.setAuthenticationManager(authenticationManager());
        authenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            final YtiUser principal = (YtiUser) authentication.getPrincipal();
            if (principal.isNewlyCreated()) {
                for (final NewlyCreatedUserListener listener : newlyCreatedUserListeners) {
                    listener.onNewlyCreatedUser(principal);
                }
            }
        });

        return authenticationFilter;
    }

    @Bean
    Filter tokenAuthenticationFilter() {

        final OncePerRequestFilter tokenAuthenticationFilter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(final HttpServletRequest request,
                                            final HttpServletResponse response,
                                            final FilterChain filterChain) throws ServletException, IOException {

                String token = parseToken(request.getHeader("Authorization"));
                if (token == null) {
                    final Cookie[] cookies = request.getCookies();
                    if (cookies != null && cookies.length > 0) {
                        for (final Cookie cookie : cookies) {
                            if (HEADER_YTITOKEN.equalsIgnoreCase(cookie.getName())) {
                                token = cookie.getValue();
                            }
                        }
                    }
                }
                if (token != null && !token.isEmpty()) {
                    try {
                        final YtiUser ytiUser = getUserForToken(token);
                        final TokenUserLogin login = resolveTokenUserLogin(ytiUser);
                        if (login != null) {
                            request.setAttribute("id", login.getId());
                            request.setAttribute("mail", login.getEmail());
                            request.setAttribute("givenname", login.getFirstName());
                            request.setAttribute("surname", login.getLastName());
                        }
                    } catch (final AuthorizationException e) {
                        logger.debug("tokenAuthenticationFilter: Token validation failed!");
                        request.setAttribute("id", null);
                        request.setAttribute("mail", null);
                        request.setAttribute("givenname", null);
                        request.setAttribute("surname", null);
                        if (!request.getPathInfo().contains("redirect")) {
                            response.setHeader("Set-Cookie", HEADER_YTITOKEN + "=deleted;path=/;HttpOnly;expires=Thu, 01 Jan 1970 00:00:00 GMT");
                            final String redirectUrl = request.getRequestURL().toString().replace("http://", "https://");
                            response.sendRedirect(redirectUrl);
                        }
                    }
                }
                filterChain.doFilter(request, response);
            }

            private @Nullable TokenUserLogin resolveTokenUserLogin(final YtiUser ytiUser) {

                if (ytiUser != null && !ytiUser.isAnonymous()) {
                    return new TokenUserLogin(ytiUser);
                } else {
                    return null;
                }
            }

            private String parseToken(final String headerString) {

                if (headerString != null && !headerString.isEmpty() && headerString.startsWith("Bearer ")) {
                    final String token = headerString.substring(7);
                    if (!token.isEmpty()) {
                        return token;
                    }
                    return null;
                }
                return null;
            }

            private YtiUser getUserForToken(final String token) throws AuthorizationException {

                final UriComponentsBuilder uriBuilder = UriComponentsBuilder
                    .fromHttpUrl(groupmanagementUrl)
                    .path("/private-api/validate");
                final String validateTokenUri = uriBuilder.build().toUriString();
                final YtiToken ytiToken = new YtiToken(token);
                final HttpEntity<YtiToken> tokenRequest = new HttpEntity<>(ytiToken);
                final ResponseEntity<User> validateResponse = restTemplate.postForEntity(validateTokenUri, tokenRequest, User.class);
                if (validateResponse != null && validateResponse.getBody() != null) {
                    final User user = validateResponse.getBody();
                    if (user != null) {
                        final Map<UUID, Set<Role>> rolesInOrganizations = new HashMap<>();
                        if (user.organization != null) {
                            for (final Organization organization : user.organization) {
                                final Set<Role> roles = organization.role.stream()
                                    .filter(RoleUtil::isRoleMappableToEnum)
                                    .map(Role::valueOf)
                                    .collect(Collectors.toSet());
                                rolesInOrganizations.put(organization.uuid, roles);
                            }
                        }
                        return new YtiUser(user.email, user.firstName, user.lastName, user.id, user.superuser, user.newlyCreated, user.tokenCreatedAt, user.tokenInvalidationAt, rolesInOrganizations, user.containerUri, user.tokenRole);
                    }
                }
                throw new AuthorizationException("Invalid token.");
            }
        };

        return tokenAuthenticationFilter;
    }

    @Bean
    Filter logoutFilter() {

        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(final HttpServletRequest request,
                                            final HttpServletResponse response,
                                            final FilterChain filterChain) throws ServletException, IOException {

                final String loggedInUser = (String) request.getAttribute("mail");
                if (loggedInUser == null || loggedInUser.isEmpty()) {
                    SecurityContextHolder.clearContext();
                }
                filterChain.doFilter(request, response);
            }
        };
    }

    @Bean
    AuthenticationProvider authenticationProvider() {

        final PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(authenticatedUserDetailsService());
        return authenticationProvider;
    }

    @Bean
    AuthenticatedUserProvider userProvider() {
        return () -> {

            final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null) {
                final Object principal = authentication.getPrincipal();

                if (principal instanceof YtiUser) {
                    return (YtiUser) principal;
                }
            }

            return YtiUser.ANONYMOUS_USER;
        };
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        final OncePerRequestFilter fakeUserSettingFilter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(final HttpServletRequest request,
                                            final HttpServletResponse response,
                                            final FilterChain filterChain) throws ServletException, IOException {

                // Don't inject fake user for public-api or otherwise it will end up in infinite loop
                if (allowFakeUser && !request.getRequestURI().contains("public-api")) {

                    final FakeUserLogin login = resolveFakeUserLogin(request);

                    if (login != null) {
                        request.setAttribute("mail", login.getEmail());
                        request.setAttribute("givenname", login.getFirstName());
                        request.setAttribute("surname", login.getLastName());
                    }
                }

                filterChain.doFilter(request, response);
            }

            private @Nullable FakeUserLogin resolveFakeUserLogin(final HttpServletRequest request) {

                final YtiUser user = userProvider().getUser();
                final String mail = request.getParameter("fake.login.mail");
                final String firstName = request.getParameter("fake.login.firstName");
                final String lastName = request.getParameter("fake.login.lastName");

                if (mail != null) {
                    return new FakeUserLogin(mail, firstName, lastName);
                } else if (!user.isAnonymous()) { // keep previously logged in user still logged in
                    return new FakeUserLogin(user.getEmail(), user.getFirstName(), user.getLastName());
                } else if (fakeUserLoginProvider != null) {
                    return fakeUserLoginProvider.getLogin();
                } else {
                    return null;
                }
            }
        };

        http.antMatcher("/**/*")
            .addFilter(authenticationFilter())
            .addFilterBefore(tokenAuthenticationFilter(), RequestAttributeAuthenticationFilter.class)
            .addFilterBefore(fakeUserSettingFilter, RequestAttributeAuthenticationFilter.class)
            .addFilterBefore(logoutFilter(), RequestAttributeAuthenticationFilter.class);

        http.csrf().disable();

        if (!allowFakeUser) {
            http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }
    }

    @Override
    public void configure(WebSecurity web) throws RuntimeException {
    }
}

class YtiToken {

    private String token;

    YtiToken(final String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(final String token) {
        this.token = token;
    }
}

