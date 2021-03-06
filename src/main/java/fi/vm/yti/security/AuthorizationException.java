package fi.vm.yti.security;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class AuthorizationException extends RuntimeException {

    public AuthorizationException(final String message) {
        super(message);
    }

    public static void check(final boolean hasRight) {
        check(hasRight, "");
    }

    public static void check(final boolean hasRight,
                             final String message) {
        if (!hasRight) {
            throw new AuthorizationException(message);
        }
    }
}
