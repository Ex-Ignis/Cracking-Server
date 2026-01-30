package com.security.cracking.controller;

import com.security.cracking.dto.HashRequestDTO;
import com.security.cracking.dto.HashResponseDTO;
import com.security.cracking.service.CrackingService;
import com.security.cracking.service.HashCracker;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class CrackingController {

    private final CrackingService crackingService;
    public CrackingController(CrackingService crackingService) {
        this.crackingService = crackingService;
    }

    @PostMapping("/hashcracking")
    public ResponseEntity<HashResponseDTO> hashCracking(@Valid @ModelAttribute HashRequestDTO hashReq) {

        if ((hashReq.getPasswd() == null || hashReq.getPasswd().isBlank()) &&
                (hashReq.getPassListF() == null || hashReq.getPassListF().isEmpty())) {

            HashResponseDTO errorResp = new HashResponseDTO();
            errorResp.setMessage("Password or PassList cant be empty");
            return ResponseEntity.badRequest().body(errorResp);
        }
        try {
            HashResponseDTO hashResp = crackingService.crackPasswd(hashReq);
            return ResponseEntity.ok().body(hashResp);
        } catch (IllegalArgumentException iae) {
            HashResponseDTO errorResp = new HashResponseDTO();
            errorResp.setMessage(iae.getMessage());
            return ResponseEntity.badRequest().body(errorResp);
        }
    }

    @GetMapping("/hashtypes")
    public ResponseEntity<List<String>> getCrackers (){
        return ResponseEntity.ok().body(crackingService.getSupportedHashTypes());
    }

}
