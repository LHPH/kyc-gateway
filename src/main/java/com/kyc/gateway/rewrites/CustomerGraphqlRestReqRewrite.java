package com.kyc.gateway.rewrites;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyc.gateway.model.GraphqlRestReq;
import lombok.RequiredArgsConstructor;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class CustomerGraphqlRestReqRewrite implements RewriteFunction<String, String> {

    private final static Logger LOGGER = LoggerFactory.getLogger(CustomerGraphqlRestReqRewrite.class);

    private final ObjectMapper objectMapper;
    private final GraphqlRestReq newBody;

    @Override
    public Publisher<String> apply(ServerWebExchange exchange, String oldBody) {

        try{

            String strNewBody = objectMapper.writeValueAsString(newBody);
            return Mono.just(strNewBody);
        }
        catch(JsonProcessingException ex){
            throw new RuntimeException(ex);
        }
    }
}