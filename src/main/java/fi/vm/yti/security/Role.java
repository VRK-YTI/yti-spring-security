package fi.vm.yti.security;

public enum Role {

    GROUP_ADMIN,
    DATA_MODEL_ADMIN,
    DATA_MODELER,
    TERMINOLOGY_ADMIN,
    TERMINOLOGIST,
    CODE_LIST_ADMIN,
    CODE_LIST_EDITOR;

    public static boolean contains(String roleString) {
        for (Role role : values()) {
            if (role.name().equals(roleString)) {
                return true;
            }
        }

        return false;
    }
}
