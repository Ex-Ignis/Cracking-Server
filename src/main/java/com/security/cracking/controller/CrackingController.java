package com.security.cracking.controller;

import com.security.cracking.dto.HashRequestDTO;
import com.security.cracking.dto.HashResponseDTO;
import com.security.cracking.service.CrackingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api")
public class CrackingController {

    private final CrackingService crackingService;

    public CrackingController(CrackingService crackingService) {
        this.crackingService = crackingService;
    }

    @PostMapping("/hashcracking")
    public ResponseEntity<HashResponseDTO> HashCracking (@ModelAttribute HashRequestDTO hashReq){

        if ((hashReq.getPasswd() == null || hashReq.getPasswd().isBlank()) &&
                (hashReq.getPassListF() == null || hashReq.getPassListF().isEmpty())) {

            HashResponseDTO errorResp = new HashResponseDTO();
            errorResp.setMessage("Password or PassList cant be empty");
            return ResponseEntity.badRequest().body(errorResp);
        }


        HashResponseDTO hashResp = crackingService.crackPasswd(hashReq);


        return ResponseEntity.ok().body(hashResp);
    }

}
