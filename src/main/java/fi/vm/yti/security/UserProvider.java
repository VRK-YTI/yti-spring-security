package fi.vm.yti.security;

import org.jetbrains.annotations.Nullable;

public interface UserProvider {
    @Nullable YtiUser getUser();
}
