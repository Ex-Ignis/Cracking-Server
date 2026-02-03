package com.security.cracking.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

@Getter
@Setter
@NoArgsConstructor
public class HashRequestDTO {

    @NotBlank(message = "Hash cant be empty")
    private String hash;

    @NotBlank(message = "HashType cant be empty")
    private String hashType;
    private String passwd;
    private MultipartFile passListF;

    private String salt;
    private MultipartFile saltListF;

    @AssertTrue(message = "Password or PassList cant be empty")
    public boolean isPasswordProvided() {
        return (passwd != null && !passwd.isBlank()) || passListF != null;
    }

}
