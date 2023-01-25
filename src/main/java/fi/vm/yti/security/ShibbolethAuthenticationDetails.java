package fi.vm.yti.security;

import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletRequest;

import org.jetbrains.annotations.NotNull;

import static java.util.Objects.requireNonNull;

public final class ShibbolethAuthenticationDetails {

    private final String id;
    private final String email;
    private final String firstName;
    private final String lastName;

    public ShibbolethAuthenticationDetails(final HttpServletRequest request) {
        this(
            getAttributeAsStringWithoutNullCheck(request, "id"),
            getAttributeAsString(request, "mail"),
            getAttributeAsString(request, "givenname"),
            getAttributeAsString(request, "surname")
        );
    }

    public ShibbolethAuthenticationDetails(final String id,
                                           final String email,
                                           final String firstName,
                                           final String lastName) {
        this.id = id;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    private static String getAttributeAsString(final HttpServletRequest request,
                                               final String attributeName) {
        final Object attribute = requireNonNull(request.getAttribute(attributeName), "Request attribute missing: " + attributeName);
        return convertLatinToUTF8(attribute.toString());
    }

    private static String getAttributeAsStringWithoutNullCheck(final HttpServletRequest request,
                                                               final String attributeName) {
        final Object attribute = request.getAttribute(attributeName);
        if (attribute != null) {
            return convertLatinToUTF8(attribute.toString());
        }
        return null;
    }

    private static @NotNull String convertLatinToUTF8(@NotNull final String s) {
        return new String(s.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
    }

    public String getId() {
        return id;
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
            "id='" + id + '\'' +
            ", email='" + email + '\'' +
            ", firstName='" + firstName + '\'' +
            ", lastName='" + lastName + '\'' +
            '}';
    }
}
