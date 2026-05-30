package com.kyc.gateway.testenc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.kyc.core.security.Aes256GcmCipherOperation;
import com.kyc.core.security.RsaCipherFacade;
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

import static com.kyc.core.util.CryptoUtil.transformAesKey;
import static com.kyc.gateway.constants.AppConstants.HEADER_SESSION_KEY;

@RestController
@Profile("check-encryption")
@RequestMapping("/test/enc")
public class TestEncryptionController {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestEncryptionController.class);

    @Autowired
    private Aes256GcmCipherOperation aesCipher;

    @Autowired
    private RsaCipherFacade rsaCipherFacade;

    @Autowired
    private ObjectMapper objectMapper;

    @PostMapping("/aes/own")
    public ResponseEntity<Mono<GatewayEncryptData>> testAesOwn(
            @RequestBody GatewayEncryptData req,
            @RequestParam(name = "mode",defaultValue = "encrypt") String mode){

        try{
            /*if("decrypt".equals(mode)){
                return ResponseEntity.ok(Mono.just(new GatewayEncryptData(aesCipher.decrypt(req.getData()))));
            }
            return ResponseEntity.ok(Mono.just(new GatewayEncryptData(aesCipher.encrypt(req.getData()))));*/
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).build();
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
            @RequestHeader(HEADER_SESSION_KEY) String aesKey,
            @RequestParam(name = "mode",defaultValue = "encrypt") String mode){
        try{

            SecretKey secretKey = transformAesKey(aesKey);

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

    @PostMapping("/aes/json/on-demand")
    public ResponseEntity<Mono<JsonNode>> testAesJsonOnDemand(
            @RequestBody JsonNode req,
            @RequestHeader(HEADER_SESSION_KEY) String aesKey,
            @RequestParam(name = "mode",defaultValue = "encrypt") String mode){
        try{

            SecretKey secretKey = transformAesKey(aesKey);
            String strJson;
            String data;
            if("decrypt".equals(mode)){

                data = req.at("/data").asText();
                strJson = aesCipher.decrypt(data,secretKey);
                return ResponseEntity.ok(Mono.just(objectMapper.readValue(strJson,JsonNode.class)));
            }

            strJson = objectMapper.writeValueAsString(req);
            data = aesCipher.encrypt(strJson,secretKey);
            ObjectNode objectNode = objectMapper.createObjectNode();
            objectNode.set("data", TextNode.valueOf(data));

            return ResponseEntity.ok(Mono.just(objectNode));
        }
        catch(Exception ex){

            LOGGER.warn("Error in encryption/decryption",ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Mono.just(objectMapper.createObjectNode().set("error",TextNode.valueOf(ex.getMessage()))));
        }
    }

    @GetMapping("/rsa/public-key")
    public ResponseEntity<Mono<Map<String,String>>> getRsaPublicKey(){

        try{

            byte [] key = rsaCipherFacade.getPublicKey().getEncoded();
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
                return ResponseEntity.ok(Mono.just(new GatewayEncryptData(rsaCipherFacade.decrypt(req.getData()))));
            }
            return ResponseEntity.ok(Mono.just(new GatewayEncryptData(rsaCipherFacade.encrypt(req.getData()))));
        }
        catch(Exception ex){

            LOGGER.warn("Error in encryption/decryption",ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Mono.just(new GatewayEncryptData("error: "+ex.getMessage())));
        }
    }

}
