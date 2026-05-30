package com.kyc.gateway.decorates;

import com.kyc.core.security.Aes256GcmCipherOperation;
import io.netty.buffer.ByteBufAllocator;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import reactor.core.publisher.Flux;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static com.kyc.core.constants.TokenConstants.BEARER_TOKEN_PREFIX;

public class DecryptRequestDecorate extends ServerHttpRequestDecorator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptRequestDecorate.class);

    private final Aes256GcmCipherOperation aesCipher;
    private final String originalBody;
    private final SecretKey secretKey;
    private HttpHeaders newHttpHeaders;

    public DecryptRequestDecorate(ServerHttpRequest delegate,
                                  String data,
                                  Aes256GcmCipherOperation aesCipher,
                                  SecretKey secretKey) {
        super(delegate);
        this.originalBody = getDecryptText(data);
        this.secretKey = secretKey;
        this.aesCipher = aesCipher;
    }

    public DecryptRequestDecorate(ServerHttpRequest delegate,
                                  Aes256GcmCipherOperation aesCipher,
                                  SecretKey secretKey) {
       this(delegate,"",aesCipher,secretKey);
    }

    @Override
    public Flux<DataBuffer> getBody() {

        if(StringUtils.isEmpty(originalBody)){
            return super.getBody();
        }
        return Flux.just(stringToBuffer(originalBody));
    }

    private DataBuffer stringToBuffer(String value){
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        NettyDataBufferFactory nettyDataBufferFactory = new
                NettyDataBufferFactory(ByteBufAllocator.DEFAULT);
        DataBuffer buffer = nettyDataBufferFactory.allocateBuffer(bytes.length);
        buffer.write(bytes);
        return buffer;
    }

    @Override
    public HttpHeaders getHeaders() {

        if(newHttpHeaders==null){

            newHttpHeaders = new HttpHeaders(super.getHeaders());
            decryptAuthorizationHeader(newHttpHeaders);
            int lengthBody = originalBody.getBytes(StandardCharsets.UTF_8).length;
            newHttpHeaders.setContentLength(lengthBody);
        }
        return newHttpHeaders;
    }

    private String getDecryptText(String encryptedText)  {

        if(StringUtils.isNotEmpty(encryptedText)){
            return aesCipher.decrypt(encryptedText,this.secretKey);
        }
        return "";
    }

    private void decryptAuthorizationHeader(HttpHeaders httpHeaders){

        String authorization = Objects.toString(httpHeaders.getFirst(HttpHeaders.AUTHORIZATION),"");
        LOGGER.info("Checking if authorization header is present");
        if(StringUtils.isNotEmpty(authorization)){

            LOGGER.info("Decrypting authorization header");

            String token = aesCipher.decrypt(authorization.replace(BEARER_TOKEN_PREFIX, ""),this.secretKey);
            httpHeaders.set(HttpHeaders.AUTHORIZATION, BEARER_TOKEN_PREFIX +token);
        }
    }
}


