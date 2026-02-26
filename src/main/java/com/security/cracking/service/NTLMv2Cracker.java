package com.security.cracking.service;

import com.security.cracking.dto.HashRequestDTO;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
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
 * Cracker para NTLMv2 (Net-NTLMv2 / NTLMv2-SSP).
 *
 * Formato capturado por Responder / Impacket:
 *   username::domain:serverChallenge:ntProofStr:blob
 *
 * Algoritmo de verificacion:
 *   1. ntHash   = MD4( UTF-16LE(password) )
 *   2. ntlmv2   = HMAC-MD5( ntHash,  UTF-16LE( username.toUpperCase() + domain ) )
 *   3. computed = HMAC-MD5( ntlmv2,  bytes(serverChallenge) + bytes(blob) )
 *   4. Si computed == ntProofStr  →  contraseña encontrada
 */
@Component
public class NTLMv2Cracker implements HashCracker {

    static { Security.addProvider(new BouncyCastleProvider()); }

    @Override
    public Optional<String> crack(HashRequestDTO hashReq) {
        NTLMv2Parts parts = parse(hashReq.getHash());

        if (hasPassword(hashReq)) {
            if (verify(hashReq.getPasswd(), parts)) {
                return Optional.of(hashReq.getPasswd());
            }
        }

        if (hasPassList(hashReq)) {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(hashReq.getPassListF().getInputStream()))) {

                String password;
                while ((password = br.readLine()) != null) {
                    if (verify(password, parts)) {
                        return Optional.of(password);
                    }
                }

            } catch (IOException e) {
                throw new RuntimeException("Error reading passlist file", e);
            }
        }

        return Optional.empty();
    }

    private record NTLMv2Parts(String username, String domain,
                               byte[] serverChallenge, byte[] ntProofStr, byte[] blob) {}

    /**
     * Parsea el hash NTLMv2 en formato Responder:
     *   username::domain:serverChallenge:ntProofStr:blob
     */
    private NTLMv2Parts parse(String raw) {
        String[] parts = raw.split(":", 6);
        if (parts.length != 6) {
            throw new IllegalArgumentException(
                "NTLMv2 hash malformado. Formato esperado: username::domain:serverChallenge:ntProofStr:blob");
        }

        String username       = parts[0];
        // parts[1] es el campo vacío del "::" entre username y domain
        String domain         = parts[2];
        byte[] serverChallenge = HexFormat.of().parseHex(parts[3]);
        byte[] ntProofStr      = HexFormat.of().parseHex(parts[4]);
        byte[] blob            = HexFormat.of().parseHex(parts[5]);

        return new NTLMv2Parts(username, domain, serverChallenge, ntProofStr, blob);
    }

    private boolean verify(String password, NTLMv2Parts parts) {
        try {
            // Paso 1: NT hash = MD4( UTF-16LE(password) )
            byte[] ntHash = md4(password.getBytes(StandardCharsets.UTF_16LE));

            // Paso 2: NTLMv2 key = HMAC-MD5( ntHash, UTF-16LE(USERNAME + DOMAIN) )
            String identity = parts.username().toUpperCase() + parts.domain();
            byte[] ntlmv2Key = hmacMD5(ntHash, identity.getBytes(StandardCharsets.UTF_16LE));

            // Paso 3: computed NTProofStr = HMAC-MD5( ntlmv2Key, serverChallenge + blob )
            byte[] message = concat(parts.serverChallenge(), parts.blob());
            byte[] computed = hmacMD5(ntlmv2Key, message);

            return MessageDigest.isEqual(computed, parts.ntProofStr());

        } catch (Exception e) {
            throw new RuntimeException("Error en verificacion NTLMv2", e);
        }
    }

    private byte[] md4(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD4");
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] hmacMD5(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(new SecretKeySpec(key, "HmacMD5"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    @Override
    public boolean supports(String hashType) {
        return "NTLMv2".equalsIgnoreCase(hashType);
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
    public boolean hasSalt(HashRequestDTO req) { return false; }

    @Override
    public boolean hasSaltList(HashRequestDTO req) { return false; }

    @Override
    public String getSupportedHashType() { return "NTLMv2"; }
}
