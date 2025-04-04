package com.kyc.gateway.service;

import com.kyc.gateway.configuration.EncryptionControlConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;

@Service
public class RequireEncryptionService {

    private final static Logger LOGGER = LoggerFactory.getLogger(RequireEncryptionService.class);

    @Autowired
    private EncryptionControlConfig encryptionControlConfig;

    public boolean requireEncryption(ServerHttpRequest serverHttpRequest){

        String remoteIp = serverHttpRequest.getRemoteAddress().getAddress().getHostAddress();
        LOGGER.info("Checking if incoming {} requires encryption",remoteIp);
        LOGGER.info("Whitelist {}",encryptionControlConfig.getWhiteList());
        return encryptionControlConfig.isEnabled() && !encryptionControlConfig.getWhiteList().contains(remoteIp);
    }
}
