package fi.vm.yti.security;

import org.jetbrains.annotations.NotNull;

public interface UserProvider {
    @NotNull YtiUser getUser();
}
