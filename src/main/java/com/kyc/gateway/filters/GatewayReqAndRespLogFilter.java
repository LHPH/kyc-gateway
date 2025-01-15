package com.kyc.gateway.filters;

import com.kyc.core.http.WebFluxReqAndRespLogger;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class GatewayReqAndRespLogFilter extends WebFluxReqAndRespLogger implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        return chain.filter(exchange
                .mutate()
                .request(logRequest(exchange))
                .response(logResponse(exchange))
                .build());
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE+6;
    }
}
