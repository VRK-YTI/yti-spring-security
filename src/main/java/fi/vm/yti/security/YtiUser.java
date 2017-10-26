package fi.vm.yti.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static java.util.Collections.unmodifiableList;

import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;

public final class YtiUser implements UserDetails {

    private static final List<GrantedAuthority> DEFAULT_AUTHORITIES =
            unmodifiableList(createAuthorityList("ROLE_USER"));

    private static final List<GrantedAuthority> ADMIN_AUTHORITIES =
            unmodifiableList(createAuthorityList("ROLE_ADMIN", "ROLE_USER"));

    private final String email;
    private final String firstName;
    private final String lastName;
    private final boolean superuser;
    private final boolean newlyCreated;
    private final Map<UUID, Set<Role>> rolesInOrganizations;

    public YtiUser(String email,
                   String firstName,
                   String lastName,
                   boolean superuser,
                   boolean newlyCreated,
                   Map<UUID, Set<Role>> rolesInOrganizations) {

        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.superuser = superuser;
        this.newlyCreated = newlyCreated;
        this.rolesInOrganizations = rolesInOrganizations;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.isSuperuser() ? ADMIN_AUTHORITIES : DEFAULT_AUTHORITIES;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    public String getFirstName() {
        return this.firstName;
    }

    public String getLastName() {
        return this.lastName;
    }

    public String getEmail() {
        return this.email;
    }

    public boolean isSuperuser() {
        return this.superuser;
    }

    public boolean isNewlyCreated() {
        return this.newlyCreated;
    }

    public Map<UUID, Set<Role>> getRolesInOrganizations() {
        return rolesInOrganizations;
    }

    public Set<Role> getRolesInOrganization(UUID organizationId) {

        Set<Role> roles = this.rolesInOrganizations.get(organizationId);

        if (roles != null) {
            return roles;
        } else {
            return emptySet();
        }
    }

    public boolean isInRoleInAnyOrganization(Role role, UUID... organizationIds) {
        return isInRoleInAnyOrganization(role, Arrays.asList(organizationIds));
    }

    public boolean isInRoleInAnyOrganization(Role role, Collection<UUID> organizationIds) {
        return isInAnyRoleInAnyOrganization(singleton(role), organizationIds);
    }

    public boolean isInAnyRoleInAnyOrganization(Collection<Role> roles, Collection<UUID> organizationIds) {
        for (UUID organizationId : organizationIds) {
            for (Role role : roles) {
                if (this.getRolesInOrganization(organizationId).contains(role)) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String toString() {
        return "YtiUser{" +
                "email='" + email + '\'' +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", superuser=" + superuser +
                ", newlyCreated=" + newlyCreated +
                ", rolesInOrganizations=" + rolesInOrganizations +
                '}';
    }
}
