package fi.vm.yti.security.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import fi.vm.yti.security.Role;

public interface RoleUtil {

    Log log = LogFactory.getLog(RoleUtil.class);

    static boolean isRoleMappableToEnum(String roleString) {

        final boolean contains = Role.contains(roleString);

        if (!contains) {
            log.warn("Cannot map role (" + roleString + ")" + " to role enum");
        }

        return contains;
    }
}
