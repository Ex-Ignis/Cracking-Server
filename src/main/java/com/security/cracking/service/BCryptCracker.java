package com.security.cracking.service;

import com.security.cracking.dto.HashRequestDTO;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Optional;

@Component
public class BCryptCracker implements HashCracker {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Override
    public Optional<String> crack(HashRequestDTO hashReq) {
        if (hasPassword(hashReq)) {
            if (encoder.matches(hashReq.getPasswd(), hashReq.getHash())) {
                return Optional.of(hashReq.getPasswd());
            }
        }
        if (hasPassList(hashReq)) {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(hashReq.getPassListF().getInputStream()))) {

                String password;
                while ((password = br.readLine()) != null) {
                    if (encoder.matches(password, hashReq.getHash())) {
                        return Optional.of(password);
                    }
                }

            } catch (IOException e) {
                throw new RuntimeException("Error reading passlist file", e);
            }
        }
        return Optional.empty();
    }

    @Override
    public boolean supports(String hashType) {
        return "BCrypt".equalsIgnoreCase(hashType);
    }

    @Override
    public boolean hasPassword(HashRequestDTO req) {
        return req.getPasswd() != null && !req.getPasswd().isBlank();
    }

    @Override
    public boolean hasPassList(HashRequestDTO req) {
        return req.getPassListF() != null && !req.getPassListF().isEmpty();
    }

    @Override
    public boolean hasSaltList(HashRequestDTO req){
        return false;
    }

    @Override
    public boolean hasSalt(HashRequestDTO req){
        return false;
    }

    @Override
    public String getSupportedHashType(){ return "BCrypt";}

}
