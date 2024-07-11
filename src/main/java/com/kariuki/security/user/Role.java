package com.kariuki.security.user;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;
import java.util.List;

import static com.kariuki.security.user.Permissions.*;

@Getter
@AllArgsConstructor
public enum Role {
    CUSTOMER(List.of(WRITE_ONE_PRODUCT)),
    ADMIN(Arrays.asList(WRITE_ONE_PRODUCT, READ_ALL_PRODUCTS));

    /**
     * This field will be assigned the permissions of each user created.
     * For this reason, it will not be final
     */
    private List<Permissions> permissions;
}
