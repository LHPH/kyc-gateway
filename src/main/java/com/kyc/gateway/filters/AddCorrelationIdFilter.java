package com.kyc.gateway.filters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static com.kyc.core.constants.GeneralConstants.CORRELATION_ID_HEADER;

@Component
public class AddCorrelationIdFilter implements GlobalFilter, Ordered {

    private final static Logger LOGGER = LoggerFactory.getLogger(AddCorrelationIdFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String correlationId = UUID.randomUUID().toString();

        LOGGER.info("[{}] Adding to the request the correlation id",correlationId);
        ServerHttpRequest request = exchange.getRequest()
                .mutate()
                .header(CORRELATION_ID_HEADER,correlationId)
                .build();
        MDC.put(CORRELATION_ID_HEADER,correlationId);

        return chain.filter(exchange
                .mutate()
                .request(request)
                .build())
                .doOnSuccess((e)-> MDC.clear());
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE+4;
    }
}
