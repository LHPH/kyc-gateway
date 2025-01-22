package com.kyc.gateway.filters;

import com.kyc.core.exception.KycRestException;
import com.kyc.core.model.jwt.TokenMetaData;
import com.kyc.core.model.web.ResponseData;
import com.kyc.core.properties.KycMessages;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static com.kyc.core.constants.GeneralConstants.CORRELATION_ID_HEADER;
import static com.kyc.gateway.constants.AppConstants.ATTR_SUB;
import static com.kyc.gateway.constants.AppConstants.ATTR_USER_TYPE;
import static com.kyc.gateway.constants.AppConstants.MSG_APP_002;

@Component
public class AuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthenticationGatewayFilterFactory.Config> {

    private final static Logger LOGGER = LoggerFactory.getLogger(AuthenticationGatewayFilterFactory.class);

    @Value("${services.internal.session-checking}")
    private String urlSessionChecking;

    @Autowired
    private RestClient restClient;

    @Autowired
    private KycMessages kycMessages;

    public AuthenticationGatewayFilterFactory(){
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {

            ServerHttpRequest req = exchange.getRequest();
            HttpHeaders httpHeaders = req.getHeaders();

            if(httpHeaders.containsKey(HttpHeaders.AUTHORIZATION)){

                LOGGER.info("Checking token");
                String token = httpHeaders.getFirst(HttpHeaders.AUTHORIZATION);

                ResponseEntity<ResponseData<TokenMetaData>> responseToken = restClient.post()
                        .uri(urlSessionChecking)
                        .header(HttpHeaders.AUTHORIZATION,token)
                        .header("channel",req.getHeaders().getFirst("channel"))
                        .retrieve()
                        .onStatus(status -> status.value() !=200 ,(request,response) ->{

                            LOGGER.error("Bad token");
                            throw KycRestException.builderRestException()
                                    .errorData(kycMessages.getMessage(MSG_APP_002))
                                    .inputData("Bad token")
                                    .outputData(response)
                                    .status(HttpStatus.UNAUTHORIZED)
                                    .build();
                        })
                        .toEntity(new ParameterizedTypeReference<>() {});

                TokenMetaData tokenMetaData = Objects.requireNonNull(responseToken.getBody()).getData();
                /*TokenMetaData tokenMetaData = new TokenMetaData();
                tokenMetaData.setRole("CUSTOMER");
                tokenMetaData.setSub("1");*/

                String role = tokenMetaData.getRole();
                LOGGER.info("{} - {}",role,config.getRoles());
                if(!config.getRoles().contains(role)){

                    throw KycRestException.builderRestException()
                            .errorData(kycMessages.getMessage(MSG_APP_002))
                            .status(HttpStatus.FORBIDDEN)
                            .build();
                }

                exchange.getAttributes().put(ATTR_USER_TYPE,role);
                exchange.getAttributes().put(ATTR_SUB,tokenMetaData.getSub());

                return chain.filter(exchange);
            }else{
                LOGGER.error("The request does not contain token");
                throw KycRestException.builderRestException()
                        .errorData(kycMessages.getMessage(MSG_APP_002))
                        .status(HttpStatus.UNAUTHORIZED)
                        .build();
            }
        };
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Collections.singletonList("roles");
    }

    @Setter
    @Getter
    public static class Config {
        private List<String> roles;
    }
}
