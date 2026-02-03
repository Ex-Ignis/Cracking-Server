package com.security.cracking.controller;

import com.security.cracking.dto.HashRequestDTO;
import com.security.cracking.dto.HashResponseDTO;
import com.security.cracking.service.CrackingService;
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
            HashResponseDTO hashResp = crackingService.crackPasswd(hashReq);
            return ResponseEntity.ok().body(hashResp);
    }

    @GetMapping("/hashtypes")
    public ResponseEntity<List<String>> getCrackers (){
        return ResponseEntity.ok().body(crackingService.getSupportedHashTypes());
    }

}
