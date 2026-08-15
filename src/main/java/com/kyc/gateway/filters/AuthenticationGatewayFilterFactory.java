package com.kyc.gateway.filters;

import com.kyc.core.constants.GeneralConstants;
import com.kyc.core.exception.KycRestException;
import com.kyc.core.model.jwt.JwtData;
import com.kyc.core.model.web.ResponseData;
import com.kyc.core.properties.KycMessages;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Collections;
import java.util.List;

import static com.kyc.gateway.constants.AppConstants.ATTR_SUB;
import static com.kyc.gateway.constants.AppConstants.ATTR_USER_TYPE;
import static com.kyc.gateway.constants.AppConstants.MSG_APP_002;

@Component
public class AuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthenticationGatewayFilterFactory.Config> {

    private final static Logger LOGGER = LoggerFactory.getLogger(AuthenticationGatewayFilterFactory.class);

    @Autowired
    private WebClient webClient;

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

            if(httpHeaders.containsHeader(HttpHeaders.AUTHORIZATION)){

                LOGGER.info("Checking token");
                String token = httpHeaders.getFirst(HttpHeaders.AUTHORIZATION);

                return webClient.get()
                        .header(HttpHeaders.AUTHORIZATION,token)
                        .header(GeneralConstants.CHANNEL,req.getHeaders().getFirst(GeneralConstants.CHANNEL))
                        .retrieve()
                        .onStatus(status -> !status.is2xxSuccessful(),(exceptionFunction) ->{

                            LOGGER.error("Bad token");
                            return exceptionFunction.bodyToMono(String.class)
                                            .flatMap(response -> {

                                                throw KycRestException.builderRestException()
                                                        .errorData(kycMessages.getMessage(MSG_APP_002))
                                                        .inputData("Bad token")
                                                        .outputData(response)
                                                        .status(HttpStatus.UNAUTHORIZED)
                                                        .build();
                                            });
                        })
                        .bodyToMono(new ParameterizedTypeReference<ResponseData<JwtData>>() {})
                        .flatMap( result -> {

                            JwtData jwtData = result.getData();
                            String role = jwtData.getRole();
                            LOGGER.info("{} - {}",role,config.getRoles());
                            if(!config.getRoles().contains(role)){

                                throw KycRestException.builderRestException()
                                        .errorData(kycMessages.getMessage(MSG_APP_002))
                                        .status(HttpStatus.FORBIDDEN)
                                        .build();
                            }

                            exchange.getAttributes().put(ATTR_USER_TYPE,role);
                            exchange.getAttributes().put(ATTR_SUB,jwtData.getSub());

                            return chain.filter(exchange);
                        });
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
