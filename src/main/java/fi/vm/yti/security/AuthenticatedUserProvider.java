package fi.vm.yti.security;

import org.jetbrains.annotations.NotNull;

public interface AuthenticatedUserProvider {
    @NotNull YtiUser getUser();
}
