package com.kyc.gateway.decorates;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyc.core.security.Aes256GcmCipherOperation;
import com.kyc.gateway.model.GatewayEncryptData;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

public class EncryptResponseDecorate extends ServerHttpResponseDecorator {

    private final static Logger LOGGER = LoggerFactory.getLogger(EncryptResponseDecorate.class);

    private final Aes256GcmCipherOperation cipherOperation;
    private final ObjectMapper objectMapper;

    public EncryptResponseDecorate(ServerHttpResponse delegate, Aes256GcmCipherOperation cipherOperation,
                                   ObjectMapper objectMapper) {
        super(delegate);
        this.cipherOperation = cipherOperation;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {

        DataBufferFactory bufferFactory = getDelegate().bufferFactory();
        if(body instanceof Flux){

            Flux<? extends DataBuffer> fluxBody = (Flux<? extends DataBuffer>) body;
            return super.writeWith(fluxBody.map(dataBuffer -> {

                try {
                    byte[] content = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(content);

                    String encryptedText = cipherOperation.encrypt(new String(content, StandardCharsets.UTF_8));

                    return bufferFactory.wrap(objectMapper.writeValueAsBytes(new GatewayEncryptData(encryptedText)));
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            }));
        }
        return super.writeWith(body);
    }
}
