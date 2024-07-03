package com.ojha.Auth_Server.email;

import lombok.Getter;

@Getter
public enum EmailTemplateName {

    ACTIVATE_ACCOUNT("activate_account"),
    Change_PASSWORD("change_password");

    private final String name;

    EmailTemplateName(String name) {
        this.name = name;
    }
}
