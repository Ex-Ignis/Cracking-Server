package com.security.cracking.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)  // omite campos null
@JsonPropertyOrder({"success", "message", "hashType", "hash", "passwdCracked", "salt"}) // orden personalizado
public class HashResponseDTO {

    @NotNull
    private boolean success = false;
    private String message;

    private String hashType;
    private String hash;
    private String passwdCracked;
    private String salt;
}
