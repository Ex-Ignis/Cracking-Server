package com.security.cracking.service;

import com.security.cracking.dto.HashRequestDTO;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.HexFormat;
import java.util.Optional;

/**
 *  NT Hash (128 bits / 16 bytes) — el hash almacenado en SAM
 *  NTHash = MD4(UTF-16LE(password))
 *  Formato volcado SAM:  usuario:rid:lmHash:ntHash
 */
@Component
public class NTHashCracker implements HashCracker{

    static {Security.addProvider(new BouncyCastleProvider());}

    @Override
    public Optional<String> crack(HashRequestDTO hashReq) {
        if (hasPassword(hashReq)) {
            if (ntlm(hashReq.getPasswd()).equalsIgnoreCase(hashReq.getHash())) {
                return Optional.of(hashReq.getPasswd());
            }
        }
        if (hasPassList(hashReq)) {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(hashReq.getPassListF().getInputStream()))) {

                String password;
                while ((password = br.readLine()) != null) {
                    if (ntlm(password).equalsIgnoreCase(hashReq.getHash())) {
                        return Optional.of(password);
                    }
                }

            } catch (IOException e) {
                throw new RuntimeException("Error reading passlist file", e);
            }
        }
        return Optional.empty();
    }

    private String ntlm(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD4");
            byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_16LE));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean supports(String hashType) {
        return "NTHash".equalsIgnoreCase(hashType);
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
    public boolean hasSalt(HashRequestDTO request) {
        return false;
    }

    @Override
    public boolean hasSaltList(HashRequestDTO request) {
        return false;
    }

    @Override
    public String getSupportedHashType() {
        return "NTHash";
    }
}
