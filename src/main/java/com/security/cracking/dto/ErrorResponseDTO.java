package com.security.cracking.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)  // omite campos null
@JsonPropertyOrder({"error", "message", "fieldErrors"}) // orden personalizado
public class ErrorResponseDTO {
    private String error; // type of error
    private String message; // optional message
    private Map<String, String> fieldErrors; // @Valid
}
