package com.kyc.gateway.configuration;

import com.kyc.core.config.AesKeyStoreConfig;
import com.kyc.core.properties.KycMessages;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClient;

@Configuration
@Import(value = {KycMessages.class, AesKeyStoreConfig.class})
public class AppConfig {

    @Bean
    public RestClient restClient(){

        return RestClient.builder()
                .build();
    }
}
