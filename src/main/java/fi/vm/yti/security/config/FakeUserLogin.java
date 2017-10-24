package fi.vm.yti.security.config;

public final class FakeUserLogin {

    private final String email;
    private final String firstName;
    private final String lastName;

    public FakeUserLogin(String email, String firstName, String lastName) {
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
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
