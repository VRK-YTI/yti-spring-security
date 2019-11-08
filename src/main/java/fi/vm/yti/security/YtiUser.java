package fi.vm.yti.security;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import static fi.vm.yti.security.util.CollectionUtil.getOrInitializeSet;
import static fi.vm.yti.security.util.CollectionUtil.unmodifiable;
import static java.util.Arrays.asList;
import static java.util.Collections.*;
import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;
import static org.springframework.util.CollectionUtils.containsAny;

public final class YtiUser implements UserDetails {

    public static final YtiUser ANONYMOUS_USER = new YtiUser(true, "anonymous@example.org", "Anonymous", "User", null, false, false, null, null, emptyMap());
    private static final List<GrantedAuthority> DEFAULT_AUTHORITIES = unmodifiableList(createAuthorityList("ROLE_USER"));
    private static final List<GrantedAuthority> ADMIN_AUTHORITIES = unmodifiableList(createAuthorityList("ROLE_ADMIN", "ROLE_USER"));

    private final boolean anonymous;
    private final String email;
    private final String firstName;
    private final String lastName;
    private final UUID id;
    private final boolean superuser;
    private final boolean newlyCreated;
    private final Map<UUID, Set<Role>> rolesInOrganizations;
    private final Map<Role, Set<UUID>> organizationsInRole;
    private final LocalDateTime tokenCreatedAt;
    private final LocalDateTime tokenInvalidationAt;

    public YtiUser(final String email,
                   final String firstName,
                   final String lastName,
                   final UUID id,
                   final boolean superuser,
                   final boolean newlyCreated,
                   final LocalDateTime tokenCreatedAt,
                   final LocalDateTime tokenInvalidationAt,
                   final Map<UUID, Set<Role>> rolesInOrganizations) {
        this(false, email, firstName, lastName, id, superuser, newlyCreated, tokenCreatedAt, tokenInvalidationAt, rolesInOrganizations);
    }

    private YtiUser(final boolean anonymous,
                    final String email,
                    final String firstName,
                    final String lastName,
                    final UUID id,
                    final boolean superuser,
                    final boolean newlyCreated,
                    final LocalDateTime tokenCreatedAt,
                    final LocalDateTime tokenInvalidationAt,
                    final Map<UUID, Set<Role>> rolesInOrganizations) {

        this.anonymous = anonymous;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.id = id;
        this.superuser = superuser;
        this.newlyCreated = newlyCreated;
        this.tokenCreatedAt = tokenCreatedAt;
        this.tokenInvalidationAt = tokenInvalidationAt;
        this.rolesInOrganizations = unmodifiable(rolesInOrganizations);

        final HashMap<Role, Set<UUID>> organizationsInRole = new HashMap<>();

        for (final Map.Entry<UUID, Set<Role>> entry : rolesInOrganizations.entrySet()) {
            for (final Role role : entry.getValue()) {
                getOrInitializeSet(organizationsInRole, role).add(entry.getKey());
            }
        }

        this.organizationsInRole = unmodifiable(organizationsInRole);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return isSuperuser() ? ADMIN_AUTHORITIES : DEFAULT_AUTHORITIES;
    }

    public boolean isAnonymous() {
        return anonymous;
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

    public UUID getId() {
        return id;
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

    public Set<Role> getRoles(final UUID organizationId) {
        return rolesInOrganizations.getOrDefault(organizationId, unmodifiableSet(emptySet()));
    }

    public Set<Role> getRoles(final UUID... organizationsIds) {
        return getRoles(asList(organizationsIds));
    }

    public Set<Role> getRoles(final Collection<UUID> organizationIds) {

        if (organizationIds.size() == 0) {
            return unmodifiableSet(emptySet());
        } else if (organizationIds.size() == 1) {
            return getRoles(organizationIds.iterator().next());
        } else {

            Set<Role> roles = EnumSet.noneOf(Role.class);

            for (UUID organizationId : organizationIds) {
                roles.addAll(getRoles(organizationId));
            }

            return unmodifiableSet(roles);
        }
    }

    public boolean isInRoleInAnyOrganization(final Role role) {
        return !getOrganizations(role).isEmpty();
    }

    public boolean isInRole(final Role role,
                            final UUID... organizationIds) {
        return isInRole(role, asList(organizationIds));
    }

    public LocalDateTime getTokenCreatedAt() {
        return this.tokenCreatedAt;
    }

    public LocalDateTime getTokenInvalidationAt() {
        return this.tokenInvalidationAt;
    }

    public boolean isInRole(final Role role,
                            final Collection<UUID> organizationIds) {
        return isInAnyRole(singleton(role), organizationIds);
    }

    public boolean isInAnyRole(final Collection<Role> roles,
                               final Collection<UUID> organizationIds) {
        return containsAny(getRoles(organizationIds), roles);
    }

    public Map<Role, Set<UUID>> getOrganizationsInRole() {
        return organizationsInRole;
    }

    public Set<UUID> getOrganizations(final Role role) {
        return organizationsInRole.getOrDefault(role, unmodifiableSet(emptySet()));
    }

    public Set<UUID> getOrganizations(final Role... roles) {
        return getOrganizations(asList(roles));
    }

    public Set<UUID> getOrganizations(final Collection<Role> roles) {

        if (roles.size() == 0) {
            return unmodifiableSet(emptySet());
        } else if (roles.size() == 1) {
            return getOrganizations(roles.iterator().next());
        } else {

            final Set<UUID> organizationIds = new HashSet<>();

            for (final Role role : roles) {
                organizationIds.addAll(getOrganizations(role));
            }

            return unmodifiableSet(organizationIds);
        }
    }

    public boolean isInOrganization(final UUID organizationId) {
        return isInOrganization(organizationId, Role.values());
    }

    public boolean isInOrganization(final UUID organizationId,
                                    final Role... roles) {
        return isInOrganization(organizationId, asList(roles));
    }

    public boolean isInOrganization(final UUID organizationId,
                                    final Collection<Role> roles) {
        return isInAnyOrganization(singleton(organizationId), roles);
    }

    public boolean isInAnyOrganization(final Collection<UUID> organizationsIds,
                                       final Collection<Role> roles) {
        return containsAny(getOrganizations(roles), organizationsIds);
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
            ", id='" + id + '\'' +
            ", superuser=" + superuser +
            ", newlyCreated=" + newlyCreated +
            ", tokenCreatedAt=" + tokenCreatedAt +
            ", tokenInvalidationAt=" + tokenInvalidationAt +
            ", rolesInOrganizations=" + rolesInOrganizations +
            '}';
    }
}
