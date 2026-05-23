package com.kyc.gateway.testenc;

import com.kyc.core.security.Aes256GcmCipherOperation;
import com.kyc.core.security.RsaCipherOperation;
import com.kyc.core.util.CryptoUtil;
import com.kyc.gateway.model.GatewayEncryptData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

@RestController
@Profile("check-encryption")
@RequestMapping("/test/enc")
public class TestEncryptionController {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestEncryptionController.class);

    @Autowired
    private Aes256GcmCipherOperation aesCipher;

    @Autowired
    private RsaCipherOperation rsaCipher;

    @PostMapping("/aes/own")
    public ResponseEntity<Mono<GatewayEncryptData>> testAesOwn(
            @RequestBody GatewayEncryptData req,
            @RequestParam(name = "mode",defaultValue = "encrypt") String mode){

        try{
            if("decrypt".equals(mode)){
                return ResponseEntity.ok(Mono.just(new GatewayEncryptData(aesCipher.decrypt(req.getData()))));
            }
            return ResponseEntity.ok(Mono.just(new GatewayEncryptData(aesCipher.encrypt(req.getData()))));
        }
        catch(Exception ex){

            LOGGER.warn("Error in encryption/decryption",ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Mono.just(new GatewayEncryptData("error: "+ex.getMessage())));
        }
    }

    @GetMapping("/aes/on-demand")
    public ResponseEntity<Mono<Map<String,String>>> getAesOnDemand(){

        try{

            byte [] key = CryptoUtil.getAesKey(256).getEncoded();
            String base64Key = Base64.getEncoder().encodeToString(key);
            return ResponseEntity.ok(Mono.just(Collections.singletonMap("data",base64Key)));
        }
        catch(Exception ex){
            LOGGER.warn("Error in getting on-demand aes key",ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Mono.just(Collections.singletonMap("data","error: " + ex.getMessage())));
        }
    }

    @PostMapping("/aes/on-demand")
    public ResponseEntity<Mono<GatewayEncryptData>> testAesOnDemand(
            @RequestBody GatewayEncryptData req,
            @RequestParam(name = "mode",defaultValue = "encrypt") String mode){
        try{

            byte [] key = Base64.getDecoder().decode(req.getKey());
            SecretKey secretKey = new SecretKeySpec(key,"AES");

            if("decrypt".equals(mode)){
                return ResponseEntity.ok(Mono.just(new GatewayEncryptData(aesCipher.decrypt(req.getData(),secretKey))));
            }
            return ResponseEntity.ok(Mono.just(new GatewayEncryptData(aesCipher.encrypt(req.getData(),secretKey))));
        }
        catch(Exception ex){

            LOGGER.warn("Error in encryption/decryption",ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Mono.just(new GatewayEncryptData("error: "+ex.getMessage())));
        }
    }

    @GetMapping("/rsa/public-key")
    public ResponseEntity<Mono<Map<String,String>>> getRsaPublicKey(){

        try{

            byte [] key = rsaCipher.getPublicKey().getEncoded();
            String base64Key = Base64.getEncoder().encodeToString(key);
            return ResponseEntity.ok(Mono.just(Collections.singletonMap("data",base64Key)));
        }
        catch(Exception ex){
            LOGGER.warn("Error in getting public key",ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Mono.just(Collections.singletonMap("data","error: " + ex.getMessage())));
        }
    }

    @PostMapping("/rsa/own")
    public ResponseEntity<Mono<GatewayEncryptData>> testRsaOwn(@RequestBody GatewayEncryptData req,
                                                               @RequestParam(name = "mode",defaultValue = "encrypt") String mode){
        try{
            if("decrypt".equals(mode)){
                return ResponseEntity.ok(Mono.just(new GatewayEncryptData(rsaCipher.decrypt(req.getData()))));
            }
            return ResponseEntity.ok(Mono.just(new GatewayEncryptData(rsaCipher.encrypt(req.getData()))));
        }
        catch(Exception ex){

            LOGGER.warn("Error in encryption/decryption",ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Mono.just(new GatewayEncryptData("error: "+ex.getMessage())));
        }
    }

}
