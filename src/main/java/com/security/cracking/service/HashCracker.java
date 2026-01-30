package com.security.cracking.service;

import com.security.cracking.dto.HashRequestDTO;
import java.util.Optional;

public interface HashCracker {

    Optional<String> crack(HashRequestDTO request);
    boolean supports(String hashType);
    boolean hasPassword(HashRequestDTO request) ;
    boolean hasPassList(HashRequestDTO request);
    public boolean hasSalt(HashRequestDTO request);
    public boolean hasSaltList(HashRequestDTO request);
    public String getSupportedHashType();

}
