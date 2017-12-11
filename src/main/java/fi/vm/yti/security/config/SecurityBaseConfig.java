package fi.vm.yti.security.config;

import fi.vm.yti.security.ShibbolethAuthenticationDetails;
import fi.vm.yti.security.AuthenticatedUserProvider;
import fi.vm.yti.security.YtiUser;
import org.jetbrains.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestAttributeAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.emptyList;

@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityBaseConfig extends WebSecurityConfigurerAdapter {

    private final String groupmanagementUrl;
    private final boolean allowFakeUser;
    private final List<NewlyCreatedUserListener> newlyCreatedUserListeners;
    private final @Nullable FakeUserLoginProvider fakeUserLoginProvider;

    @Autowired
    SecurityBaseConfig(@Value("${groupmanagement.url}") String groupmanagementUrl,
                       @Value("${fake.login.allowed:false}") boolean allowFakeUser,
                       Optional<List<NewlyCreatedUserListener>> newlyCreatedUserListeners,
                       Optional<FakeUserLoginProvider> fakeUserLoginProvider) {

        this.groupmanagementUrl = groupmanagementUrl;
        this.allowFakeUser = fakeUserLoginProvider.isPresent() || allowFakeUser;
        this.newlyCreatedUserListeners = newlyCreatedUserListeners.orElse(emptyList());
        this.fakeUserLoginProvider = fakeUserLoginProvider.orElse(null);
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

        RequestAttributeAuthenticationFilter authenticationFilter = new RequestAttributeAuthenticationFilter();
        authenticationFilter.setPrincipalEnvironmentVariable("mail");
        authenticationFilter.setExceptionIfVariableMissing(false);
        authenticationFilter.setCheckForPrincipalChanges(true);
        authenticationFilter.setInvalidateSessionOnPrincipalChange(true);
        authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource());
        authenticationFilter.setAuthenticationManager(authenticationManager());
        authenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {

            YtiUser principal = (YtiUser) authentication.getPrincipal();

            if (principal.isNewlyCreated()) {
                for (NewlyCreatedUserListener listener : newlyCreatedUserListeners) {
                    listener.onNewlyCreatedUser(principal);
                }
            }
        });

        return authenticationFilter;
    }

    @Bean
    AuthenticationProvider authenticationProvider() {

        PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(authenticatedUserDetailsService());
        return authenticationProvider;
    }

    @Bean
    AuthenticatedUserProvider userProvider() {
        return () -> {

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null) {
                Object principal = authentication.getPrincipal();

                if (principal instanceof YtiUser) {
                    return (YtiUser) principal;
                }
            }

            return YtiUser.ANONYMOUS_USER;
        };
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

                // Don't inject fake user for public-api or otherwise it will end up in infinite loop
                if (allowFakeUser && !request.getRequestURI().contains("public-api")) {

                    FakeUserLogin login = resolveFakeUserLogin(request);

                    if (login != null) {
                        request.setAttribute("mail", login.getEmail());
                        request.setAttribute("givenname", login.getFirstName());
                        request.setAttribute("surname", login.getLastName());
                    }
                }

                filterChain.doFilter(request, response);
            }

            private @Nullable FakeUserLogin resolveFakeUserLogin(HttpServletRequest request) {

                YtiUser user = userProvider().getUser();
                String mail = request.getParameter("fake.login.mail");
                String firstName = request.getParameter("fake.login.firstName");
                String lastName = request.getParameter("fake.login.lastName");

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
                .addFilterBefore(filter, RequestAttributeAuthenticationFilter.class);

        http.csrf().disable();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
    }
}
