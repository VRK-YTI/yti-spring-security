package fi.vm.yti.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

import static fi.vm.yti.security.util.CollectionUtil.getOrInitializeSet;
import static fi.vm.yti.security.util.CollectionUtil.unmodifiable;
import static java.util.Arrays.asList;
import static java.util.Collections.*;
import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;
import static org.springframework.util.CollectionUtils.containsAny;

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
    private final Map<Role, Set<UUID>> organizationsInRole;

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
        this.rolesInOrganizations = unmodifiable(rolesInOrganizations);

        HashMap<Role, Set<UUID>> organizationsInRole = new HashMap<>();

        for (Map.Entry<UUID, Set<Role>> entry : rolesInOrganizations.entrySet()) {
            for (Role role : entry.getValue()) {
                getOrInitializeSet(organizationsInRole, role).add(entry.getKey());
            }
        }

        this.organizationsInRole = unmodifiable(organizationsInRole);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return isSuperuser() ? ADMIN_AUTHORITIES : DEFAULT_AUTHORITIES;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return email;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getEmail() {
        return email;
    }

    public boolean isSuperuser() {
        return superuser;
    }

    public boolean isNewlyCreated() {
        return newlyCreated;
    }

    public Map<UUID, Set<Role>> getRolesInOrganizations() {
        return rolesInOrganizations;
    }

    public Set<Role> getRolesInOrganization(UUID organizationId) {
        return rolesInOrganizations.getOrDefault(organizationId, unmodifiableSet(emptySet()));
    }

    public Set<Role> getRolesInOrganizations(UUID... organizationsIds) {
        return getRolesInOrganizations(asList(organizationsIds));
    }

    public Set<Role> getRolesInOrganizations(Collection<UUID> organizationIds) {

        Set<Role> roles = EnumSet.noneOf(Role.class);

        for (UUID organizationId : organizationIds) {
            roles.addAll(getRolesInOrganization(organizationId));
        }

        return unmodifiableSet(roles);
    }

    public boolean isInRoleInAnyOrganization(Role role, UUID... organizationIds) {
        return isInRoleInAnyOrganization(role, asList(organizationIds));
    }

    public boolean isInRoleInAnyOrganization(Role role, Collection<UUID> organizationIds) {
        return isInAnyRoleInAnyOrganization(singleton(role), organizationIds);
    }

    public boolean isInAnyRoleInAnyOrganization(Collection<Role> roles, Collection<UUID> organizationIds) {
        return containsAny(getRolesInOrganizations(organizationIds), roles);
    }

    public Map<Role, Set<UUID>> getOrganizationsInRole() {
        return organizationsInRole;
    }

    public Set<UUID> getOrganizationsInRole(Role role) {
        return organizationsInRole.getOrDefault(role, unmodifiableSet(emptySet()));
    }

    public Set<UUID> getOrganizationsInRoles(Role... roles) {
        return getOrganizationsInRoles(asList(roles));
    }

    public Set<UUID> getOrganizationsInRoles(Collection<Role> roles) {

        Set<UUID> organizationIds = new HashSet<>();

        for (Role role : roles) {
            organizationIds.addAll(getOrganizationsInRole(role));
        }

        return unmodifiableSet(organizationIds);
    }

    public boolean isInOrganizationInAnyRole(UUID organizationId) {
        return isInOrganizationInAnyRole(organizationId, Role.values());
    }

    public boolean isInOrganizationInAnyRole(UUID organizationId, Role... roles) {
        return isInOrganizationInAnyRole(organizationId, asList(roles));
    }

    public boolean isInOrganizationInAnyRole(UUID organizationId, Collection<Role> roles) {
        return isInAnyOrganizationInAnyRole(singleton(organizationId), roles);
    }

    public boolean isInAnyOrganizationInAnyRole(Collection<UUID> organizationsIds, Collection<Role> roles) {
        return containsAny(getOrganizationsInRoles(roles), organizationsIds);
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
