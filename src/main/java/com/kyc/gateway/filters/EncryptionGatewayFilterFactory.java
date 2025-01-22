package com.kyc.gateway.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyc.core.properties.KycMessages;
import com.kyc.core.security.Aes256GcmCipherOperation;
import com.kyc.gateway.decorates.DecryptRequestDecorate;
import com.kyc.gateway.decorates.EncryptResponseDecorate;
import com.kyc.gateway.model.GatewayEncryptData;
import com.kyc.gateway.service.RequireEncryptionService;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class EncryptionGatewayFilterFactory implements GlobalFilter, Ordered {

    private final static Logger LOGGER = LoggerFactory.getLogger(EncryptionGatewayFilterFactory.class);

    @Autowired
    private Aes256GcmCipherOperation aesCipher;

    @Autowired
    private KycMessages kycMessages;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RequireEncryptionService requireEncryptionService;


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest req = exchange.getRequest();
        HttpHeaders httpHeaders = req.getHeaders();

        ServerHttpResponse response = exchange.getResponse();

        long contentLength = exchange.getRequest().getHeaders().getContentLength();
        ServerHttpResponseDecorator decorateResponse = new EncryptResponseDecorate(response,aesCipher,objectMapper);

        if(!requireEncryptionService.requireEncryption(req)){

            LOGGER.info("The request does not required encrypting/decrypting");
            return chain.filter(exchange);
        }

        LOGGER.info("Start process to decrypt/encrypt request/response");
        if(contentLength>0){

            return DataBufferUtils.join(exchange.getRequest().getBody()).flatMap(dataBuffer -> {

                DataBufferUtils.retain(dataBuffer);//Flux.just(dataBuffer.slice(0, dataBuffer.readableByteCount())
                Flux<DataBuffer> cachedFlux = Flux.defer(() -> Flux.just(dataBuffer.split(dataBuffer.readableByteCount())));
                String encryptedBody = toRaw(cachedFlux);

                String originalBody = getOriginalBody(encryptedBody);
                int lengthBody = originalBody.getBytes(StandardCharsets.UTF_8).length;
                httpHeaders.setContentLength(lengthBody);

                decryptAuthorizationHeader(exchange);
                ServerHttpRequestDecorator decorateRequest = new DecryptRequestDecorate(req,originalBody);

                return chain.filter(exchange.mutate()
                        .request(decorateRequest)
                        .response(decorateResponse).build());
            });
        }
        else{

            decryptAuthorizationHeader(exchange);
            ServerHttpRequestDecorator decorateRequest = new DecryptRequestDecorate(req);

            return chain.filter(exchange.mutate()
                    .request(decorateRequest)
                    .response(decorateResponse).build());
        }
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE+5;
    } //precedence over NettyWriteResponseFilter

    private static String toRaw(Flux<DataBuffer> body) {
        AtomicReference<String> rawRef = new AtomicReference<>();
        body.subscribe(buffer -> {
            byte[] bytes = new byte[buffer.readableByteCount()];
            buffer.read(bytes);
            DataBufferUtils.release(buffer);
            rawRef.set(Strings.fromUTF8ByteArray(bytes));
        });
        return rawRef.get();
    }

    private String getOriginalBody(String encryptedBody)  {

        if(StringUtils.isNotEmpty(encryptedBody)){

            try {
                GatewayEncryptData inputData = objectMapper.readValue(encryptedBody, GatewayEncryptData.class);
                return aesCipher.decrypt(inputData.getData());
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
        return "";
    }

    private void decryptAuthorizationHeader(ServerWebExchange exchange){

        HttpHeaders httpHeaders = exchange.getRequest().getHeaders();

        String authorization = Objects.toString(httpHeaders.getFirst(HttpHeaders.AUTHORIZATION),"");
        LOGGER.info("Checking if authorization header is present");
        if(StringUtils.isNotEmpty(authorization)){

            LOGGER.info("Decrypting authorization header");
            exchange.getRequest()
                    .mutate()
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + aesCipher.decrypt(authorization.replace("Bearer ", "")))
                    .build();
        }
    }


}
