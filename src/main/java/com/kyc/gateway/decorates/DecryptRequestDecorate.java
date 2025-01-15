package com.kyc.gateway.decorates;

import io.netty.buffer.ByteBufAllocator;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import reactor.core.publisher.Flux;

import java.nio.charset.StandardCharsets;

public class DecryptRequestDecorate extends ServerHttpRequestDecorator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptRequestDecorate.class);

    private final String originalBody;

    public DecryptRequestDecorate(ServerHttpRequest delegate, String originalBody) {
        super(delegate);
        this.originalBody = originalBody;
    }

    public DecryptRequestDecorate(ServerHttpRequest delegate) {
        super(delegate);
        this.originalBody="";
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

}


