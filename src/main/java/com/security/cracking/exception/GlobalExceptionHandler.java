package com.security.cracking.exception;

import com.security.cracking.dto.ErrorResponseDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice //anotacion para interceptar excepciones
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class) // generico
    public ResponseEntity<ErrorResponseDTO> handleException(Exception e){
        ErrorResponseDTO errorRes = new ErrorResponseDTO();
        errorRes.setError(e.getMessage());
        return ResponseEntity.internalServerError().body(errorRes);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class) // para los @Valid
    public ResponseEntity<ErrorResponseDTO> handleMethodArgumentNotValidException(MethodArgumentNotValidException  manve){
        ErrorResponseDTO error = new ErrorResponseDTO();
        error.setError("Validation failed");
        error.setMessage("Check Params");
        error.setFieldErrors(manve.getBindingResult()
                .getFieldErrors()
                .stream()
                .collect(Collectors.toMap(
                        FieldError::getField,
                        FieldError::getDefaultMessage,
                        (msg1, msg2) -> msg1  // si duplicados, quedarse con el primero
                )));
        return ResponseEntity.badRequest().body(error);
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<ErrorResponseDTO> handleIOException(IOException ioe){
        ErrorResponseDTO errorRes = new ErrorResponseDTO();
        errorRes.setError(ioe.getMessage());
        errorRes.setMessage("Check file format");
        return ResponseEntity.status(422).body(errorRes);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponseDTO> handleIllegalArgumentException(IllegalArgumentException iae){
        ErrorResponseDTO errorRes = new ErrorResponseDTO();
        errorRes.setError(iae.getMessage());
        errorRes.setMessage("Try endpoint /hashtypes");
        return ResponseEntity.badRequest().body(errorRes);
    }

}
