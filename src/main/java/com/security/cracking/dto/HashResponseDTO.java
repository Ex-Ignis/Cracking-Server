package com.security.cracking.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class HashResponseDTO {

    @NotNull
    private boolean success = false;
    private String message;

    private String hash;
    private String hashType;
    private String passwdCracked;

}
