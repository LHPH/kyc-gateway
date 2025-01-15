package com.kyc.gateway.service;

import com.kyc.gateway.configuration.EncryptionControlConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;

@Service
public class RequireEncryptionService {

    @Autowired
    private EncryptionControlConfig encryptionControlConfig;

    public boolean requireEncryption(ServerHttpRequest serverHttpRequest){

        String remoteIp = serverHttpRequest.getRemoteAddress().getAddress().getHostAddress();
        return encryptionControlConfig.isEnabled() && !encryptionControlConfig.getWhiteList().contains(remoteIp);
    }
}
