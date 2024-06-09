package com.kyc.gateway.filters;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class AuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthenticationGatewayFilterFactory.Config> {

    @Value("${services.internal.session-checking}")
    private String urlSessionChecking;

    @Autowired
    private RestClient restClient;

    public AuthenticationGatewayFilterFactory(){
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {

            ServerHttpRequest req = exchange.getRequest();

            if(req.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){

                String token = req.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

                restClient.post()
                        .uri(urlSessionChecking)
                        .header(HttpHeaders.AUTHORIZATION,token)
                        .header("channel",req.getHeaders().getFirst("channel"))
                        .retrieve()
                        .onStatus(status -> status.value() !=200 ,(request,response) ->{
                            throw new RuntimeException("Bad Token");
                        })
                        .toBodilessEntity();

                return chain.filter(exchange);
            }else{
                throw new RuntimeException("Bad");
            }
        };
    }

    public static class Config {}
}
