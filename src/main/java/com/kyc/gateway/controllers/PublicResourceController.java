package com.kyc.gateway.controllers;

import com.kyc.core.security.RsaCipherFacade;
import com.kyc.core.security.RsaCipherOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/gateway/public")
public class PublicResourceController {

    private static final Logger LOGGER = LoggerFactory.getLogger(PublicResourceController.class);

    @Autowired
    private RsaCipherFacade rsaCipherFacade;

    @GetMapping("/public-key")
    public ResponseEntity<Mono<Map<String,String>>> getGatewayPublicKey(){

        byte [] key = rsaCipherFacade.getPublicKey().getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(key);
        LOGGER.info("Returning the public key data to customers");
        return ResponseEntity.ok(Mono.just(Collections.singletonMap("data",base64Key)));
    }
}
