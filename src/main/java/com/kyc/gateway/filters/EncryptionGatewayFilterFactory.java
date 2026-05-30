package com.kyc.gateway.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyc.core.exception.KycRestException;
import com.kyc.core.properties.KycMessages;
import com.kyc.core.security.Aes256GcmCipherOperation;
import com.kyc.core.security.RsaCipherFacade;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import static com.kyc.core.constants.TokenConstants.BEARER_TOKEN_PREFIX;
import static com.kyc.core.util.CryptoUtil.transformAesKey;
import static com.kyc.gateway.constants.AppConstants.HEADER_SESSION_KEY;
import static com.kyc.gateway.constants.AppConstants.MSG_APP_002;

@Component
public class EncryptionGatewayFilterFactory implements GlobalFilter, Ordered {

    private final static Logger LOGGER = LoggerFactory.getLogger(EncryptionGatewayFilterFactory.class);

    @Autowired
    private Aes256GcmCipherOperation aesCipher;

    @Autowired
    private RsaCipherFacade rsaCipherFacade;

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

        if(!requireEncryptionService.requireEncryption(req)){

            LOGGER.info("The request does not required encrypting/decrypting");
            return chain.filter(exchange);
        }

        if(!httpHeaders.containsKey(HEADER_SESSION_KEY)){
            LOGGER.error("The request does not contain key");
            throw KycRestException.builderRestException()
                    .errorData(kycMessages.getMessage(MSG_APP_002))
                    .status(HttpStatus.UNAUTHORIZED)
                    .build();
        }

        String key = rsaCipherFacade.decrypt(httpHeaders.getFirst(HEADER_SESSION_KEY));
        SecretKey aesKey = transformAesKey(key);
        ServerHttpResponse response = exchange.getResponse();

        long contentLength = httpHeaders.getContentLength();
        ServerHttpResponseDecorator decorateResponse = new EncryptResponseDecorate(response,aesCipher,objectMapper,aesKey);

        LOGGER.info("Start process to decrypt/encrypt request/response");
        if(contentLength>0){

            return DataBufferUtils.join(exchange.getRequest().getBody()).flatMap(dataBuffer -> {

                DataBufferUtils.retain(dataBuffer);//Flux.just(dataBuffer.slice(0, dataBuffer.readableByteCount())
                Flux<DataBuffer> cachedFlux = Flux.defer(() -> Flux.just(dataBuffer.split(dataBuffer.readableByteCount())));
                String rawBody = toRaw(cachedFlux);

                GatewayEncryptData requestData = transformRawData(rawBody);
                ServerHttpRequestDecorator decorateRequest = new DecryptRequestDecorate(req,requestData.getData(),aesCipher,aesKey);

                return chain.filter(exchange.mutate()
                        .request(decorateRequest)
                        .response(decorateResponse).build());
            });
        }
        else{

            ServerHttpRequestDecorator decorateRequest = new DecryptRequestDecorate(req,aesCipher,aesKey);

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

    private GatewayEncryptData transformRawData(String rawBody){

        if(StringUtils.isNotEmpty(rawBody)){

            try {
                return objectMapper.readValue(rawBody, GatewayEncryptData.class);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
        return new GatewayEncryptData("");
    }

}
