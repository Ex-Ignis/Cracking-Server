package com.security.cracking.service;

import com.security.cracking.dto.HashRequestDTO;
import com.security.cracking.dto.HashResponseDTO;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Optional;

@Service
public class CrackingService {

    public HashResponseDTO crackPasswd(HashRequestDTO hashReq){
        HashResponseDTO hashResp = null;
        switch (hashReq.getHashType()){
            case "BCrypt": {
                hashResp = crackBcrypt(hashReq);
                break;
            }
        }

        return hashResp;
    }

    public HashResponseDTO crackBcrypt(HashRequestDTO hashReq){
        HashResponseDTO hashResp = new HashResponseDTO();
        BCryptPasswordEncoder bCrypt = new BCryptPasswordEncoder();
        if (hashReq.getPasswd() != null && !hashReq.getPasswd().isBlank()){
            if(bCrypt.matches(hashReq.getPasswd(), hashReq.getHash())){
                hashResp.setSuccess(true);
                hashResp.setHash(hashReq.getHash());
                hashResp.setHashType(hashReq.getHashType());
                hashResp.setPasswdCracked(hashReq.getPasswd());
                hashResp.setMessage("Hash [" + hashReq.getHash() + "] Cracked: " + hashReq.getPasswd());
                return hashResp;
            }
        }
        if (hashReq.getPassListF() != null && !hashReq.getPassListF().isEmpty()){
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(hashReq.getPassListF().getInputStream()))) {

                String password;
                while ((password = br.readLine()) != null) {

                    if (bCrypt.matches(password, hashReq.getHash())) {
                        hashResp.setSuccess(true);
                        hashResp.setHash(hashReq.getHash());
                        hashResp.setHashType(hashReq.getHashType());
                        hashResp.setPasswdCracked(password);
                        hashResp.setMessage("Hash [" + hashReq.getHash() + "] Cracked: " + password);
                        return hashResp;
                    }
                }

            } catch (IOException e) {
                throw new RuntimeException("Error reading passlist file", e);
            }
        }

        return hashResp;
    }

}
