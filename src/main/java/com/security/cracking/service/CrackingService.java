package com.security.cracking.service;

import com.security.cracking.dto.HashRequestDTO;
import com.security.cracking.dto.HashResponseDTO;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CrackingService {

    private final List<HashCracker> crackers;

    public CrackingService(List<HashCracker> crackers) {
        this.crackers = crackers;
    }

    public HashResponseDTO crackPasswd(HashRequestDTO hashReq) {
        return crackers.stream()
                .filter(cracker -> cracker.supports(hashReq.getHashType()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported hash type: " + hashReq.getHashType()))
                .crack(hashReq)
                .map(pwd -> success(hashReq, pwd))
                .orElse(fail(hashReq, "Hash not cracked"));
    }

    public List<String>  getSupportedHashTypes() {
       return crackers.stream()
               .map(HashCracker::getSupportedHashType)
               .toList();
    }

    /**
     * Auxiliares
     */

    private HashResponseDTO success(HashRequestDTO req, String password) {
        HashResponseDTO r = new HashResponseDTO();
        r.setSuccess(true);
        r.setHash(req.getHash());
        r.setHashType(req.getHashType());
        r.setPasswdCracked(password);
        r.setMessage("Hash cracked");
        return r;
    }

    private HashResponseDTO fail(HashRequestDTO req, String msg) {
        HashResponseDTO r = new HashResponseDTO();
        r.setSuccess(false);
        r.setHash(req.getHash());
        r.setHashType(req.getHashType());
        r.setMessage(msg);
        return r;
    }

}
