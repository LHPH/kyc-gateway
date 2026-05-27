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
        String url = serverHttpRequest.getPath().toString();
        LOGGER.info("Checking if incoming ip {} and url {} requires encryption",remoteIp,url);
        EncryptionControlConfig.EncryptionControlWhiteList whiteList = encryptionControlConfig.getWhiteList();
        LOGGER.info("Whitelist {}",whiteList);

        if(encryptionControlConfig.isEnabled()){

            boolean matchIp = whiteList.getIps().contains(remoteIp);
            boolean matchUrl = whiteList.getPaths().contains(url);

            LOGGER.info("Match Ip {}, Match URL: {}",matchIp,matchUrl);
            return !(matchIp || matchUrl);
        }

        return false;
    }
}
