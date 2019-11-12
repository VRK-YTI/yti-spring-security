package fi.vm.yti.security.config;

import org.jetbrains.annotations.Nullable;

public final class FakeUserLogin {

    private final String email;
    private final String firstName;
    private final String lastName;

    public FakeUserLogin(final String email,
                         @Nullable final String firstName,
                         @Nullable final String lastName) {
        this.email = email;
        this.firstName = firstName != null ? firstName : "";
        this.lastName = lastName != null ? lastName : "";
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
