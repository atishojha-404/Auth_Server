package com.ojha.Auth_Server.Token;

public enum TokenType {
    FIRST_VERIFY("FIRST_VERIFY"),
    Change_PWD("CHANGE_PWD");

    public final String value;

    TokenType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
