package com.security.cracking.dto;

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

    @NotBlank
    private String hash;

    private String hashType;
    private String passwd;
    private MultipartFile passListF;

}
