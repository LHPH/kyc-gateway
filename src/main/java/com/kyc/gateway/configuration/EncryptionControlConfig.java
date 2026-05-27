package com.kyc.gateway.configuration;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "kyc-config.encryption")
@Setter
@Getter
public class EncryptionControlConfig {

    private boolean enabled;

    private EncryptionControlWhiteList whiteList = new EncryptionControlWhiteList();

    @Data
    @NoArgsConstructor
    public static class EncryptionControlWhiteList{

        private List<String> ips = new ArrayList<>();
        private List<String> paths = new ArrayList<>();
    }
}
