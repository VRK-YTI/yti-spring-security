package fi.vm.yti.security;

import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;

import org.jetbrains.annotations.NotNull;

import static java.util.Objects.requireNonNull;

public final class ShibbolethAuthenticationDetails {

    private final String email;
    private final String firstName;
    private final String lastName;

    public ShibbolethAuthenticationDetails(final HttpServletRequest request) {
        this(
            getAttributeAsString(request, "mail"),
            getAttributeAsString(request, "givenname"),
            getAttributeAsString(request, "surname")
        );
    }

    public ShibbolethAuthenticationDetails(final String email,
                                           final String firstName,
                                           final String lastName) {
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    private static String getAttributeAsString(final HttpServletRequest request,
                                               final String attributeName) {

        Object attribute = requireNonNull(request.getAttribute(attributeName), "Request attribute missing: " + attributeName);
        return convertLatinToUTF8(attribute.toString());
    }

    private static @NotNull String convertLatinToUTF8(@NotNull final String s) {
        return new String(s.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
    }

    public String getEmail() {
        return email;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    @Override
    public String toString() {
        return "ShibbolethAuthenticationDetails{" +
            "email='" + email + '\'' +
            ", firstName='" + firstName + '\'' +
            ", lastName='" + lastName + '\'' +
            '}';
    }
}