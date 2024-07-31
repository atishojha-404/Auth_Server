package com.ojha.Auth_Server.constants;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GlobalResponse <T> {

    private T data;
    private int status;
    private String path;
    private String message;
    private boolean success;
    private Long timestamp;
}