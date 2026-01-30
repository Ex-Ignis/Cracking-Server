package com.security.cracking.service;

import com.security.cracking.dto.HashRequestDTO;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Optional;

/**
 * - Aguanta GPU
 * - Necesita Mucha Memoria, Mucha RAM
 *
 * Parameters:
 * Tamaño salt
 * Tamaño hash
 * Paralelismo
 * Coste Memoria
 * Iteraciones
 * $argon2<type>$v=<version>$m=<mem>,t=<time>,p=<parallel>$<salt>$<hash>
 */

@Component
public class Argon2Cracker implements HashCracker{

    private final Argon2PasswordEncoder encoder =
            Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

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
        return "Argon2".equalsIgnoreCase(hashType);
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
    public boolean hasSalt(HashRequestDTO req){
        return false;
    }

    @Override
    public boolean hasSaltList(HashRequestDTO req){
        return false;
    }

    @Override
    public String getSupportedHashType(){ return "Argon2";}
}
