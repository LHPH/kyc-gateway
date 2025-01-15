package com.kyc.gateway.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "kyc-config.encryption")
@Setter
@Getter
public class EncryptionControlConfig {

    private boolean enabled;

    private List<String> whiteList;
}
