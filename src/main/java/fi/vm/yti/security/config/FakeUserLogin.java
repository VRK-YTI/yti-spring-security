package fi.vm.yti.security.config;

import org.jetbrains.annotations.Nullable;

public final class FakeUserLogin {

    private final String email;
    private final String firstName;
    private final String lastName;

    public FakeUserLogin(String email, @Nullable  String firstName, @Nullable String lastName) {
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
