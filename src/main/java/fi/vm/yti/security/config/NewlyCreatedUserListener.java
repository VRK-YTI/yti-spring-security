package fi.vm.yti.security.config;

import fi.vm.yti.security.YtiUser;

public interface NewlyCreatedUserListener {
    void onNewlyCreatedUser(final YtiUser user);
}
