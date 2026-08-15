package com.kyc.gateway.controllers;

import com.kyc.core.security.RsaCipherFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.StringNode;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;

@RestController
@RequestMapping("/gateway/public")
public class PublicResourceController {

    private static final Logger LOGGER = LoggerFactory.getLogger(PublicResourceController.class);

    @Autowired
    private RsaCipherFacade rsaCipherFacade;

    @Autowired
    private JsonMapper JsonMapper;
    @Autowired
    private JsonMapper jsonMapper;

    @GetMapping("/public-key")
    public ResponseEntity<Mono<JsonNode>> getGatewayPublicKey() throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte [] key = rsaCipherFacade.getPublicKey().getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(key);
        byte [] hashKey = digest.digest(key);
        LOGGER.info("Returning the public key data to customers");

        ObjectNode dataNode = jsonMapper.createObjectNode();
        dataNode.set("kid", StringNode.valueOf(HexFormat.of().formatHex(hashKey)));
        dataNode.set("key", StringNode.valueOf(base64Key));

        ObjectNode rootNode = jsonMapper.createObjectNode();
        rootNode.set("data",dataNode);

        return ResponseEntity.ok(Mono.just(rootNode));
    }
}
