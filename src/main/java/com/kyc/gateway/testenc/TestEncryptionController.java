package com.kyc.gateway.testenc;

import com.kyc.core.security.Aes256GcmCipherOperation;
import com.kyc.gateway.model.GatewayEncryptData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@Profile("check-encryption")
@RestController
public class TestEncryptionController {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestEncryptionController.class);

    @Autowired
    private Aes256GcmCipherOperation aesCipher;

    @PostMapping("/test-enc")
    public ResponseEntity<Mono<GatewayEncryptData>> testEnc(@RequestBody GatewayEncryptData req,
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
}
