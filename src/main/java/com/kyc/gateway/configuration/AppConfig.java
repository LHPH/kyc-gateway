package com.kyc.gateway.configuration;

import com.kyc.core.config.AesKeyStoreConfig;
import com.kyc.core.config.BuildDetailConfig;
import com.kyc.core.properties.KycMessages;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.reactive.function.client.WebClientSsl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.function.client.WebClient;

;

@Configuration
@Import(value = {BuildDetailConfig.class,KycMessages.class, AesKeyStoreConfig.class})
public class AppConfig {

    @Value("${services.internal.session-checking}")
    private String urlSessionChecking;

    @Bean
    @Profile("prod")
    public WebClient webClient(WebClient.Builder builder, WebClientSsl webClientSsl){

        return builder.apply(webClientSsl.fromBundle("kyc-bundle"))
                .baseUrl(urlSessionChecking)
                .build();
    }

    @Bean
    @Profile("dev")
    public WebClient webClientDev(WebClient.Builder builder){

        return builder
                .baseUrl(urlSessionChecking)
                .build();
    }
}
