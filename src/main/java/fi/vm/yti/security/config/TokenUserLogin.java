package fi.vm.yti.security.config;

import fi.vm.yti.security.YtiUser;

public final class TokenUserLogin {

    private final String email;
    private final String firstName;
    private final String lastName;

    public TokenUserLogin(final YtiUser ytiUser) {
        this.email = ytiUser.getEmail();
        this.firstName = ytiUser.getFirstName();
        this.lastName = ytiUser.getLastName();
    }

    String getEmail() {
        return email;
    }

    String getFirstName() {
        return firstName;
    }

    String getLastName() {
        return lastName;
    }
}
