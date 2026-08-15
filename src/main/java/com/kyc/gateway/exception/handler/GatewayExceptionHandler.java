package com.kyc.gateway.exception.handler;

import com.kyc.core.exception.KycRestException;
import com.kyc.core.model.web.ResponseData;
import com.kyc.core.properties.KycMessages;
import com.kyc.core.security.Aes256GcmCipherOperation;
import com.kyc.core.security.RsaCipherFacade;
import com.kyc.gateway.model.GatewayEncryptData;
import com.kyc.gateway.service.RequireEncryptionService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.error.ErrorWebExceptionHandler;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

import javax.crypto.SecretKey;

import static com.kyc.core.util.CryptoUtil.transformAesKey;
import static com.kyc.gateway.constants.AppConstants.HEADER_SESSION_KEY;
import static com.kyc.gateway.constants.AppConstants.MSG_APP_001;

@Component
public class GatewayExceptionHandler implements ErrorWebExceptionHandler {

    private static final Logger LOGGER = LogManager.getLogger(GatewayExceptionHandler.class);

    @Autowired
    private KycMessages kycMessages;

    @Autowired
    private RequireEncryptionService requireEncryptionService;

    @Autowired
    private Aes256GcmCipherOperation aes256GcmCipherOperation;

    @Autowired
    private RsaCipherFacade rsaCipherFacade;

    @Autowired
    private JsonMapper jsonMapper;

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {

        LOGGER.error(" ", ex);

        ServerHttpResponse serverHttpResponse = exchange.getResponse();
        DataBufferFactory bufferFactory = serverHttpResponse.bufferFactory();

        DataBuffer dataBuffer;
        HttpStatus httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        try {

            Object response = prepareResponse(exchange,ex);
            httpStatus = prepareHttpStatus(ex);
            dataBuffer = bufferFactory.wrap(jsonMapper.writeValueAsBytes(response));

        } catch (JacksonException e) {
            dataBuffer = bufferFactory.wrap("".getBytes());
            LOGGER.error(" ", e);
        }

        serverHttpResponse.setStatusCode(httpStatus);
        serverHttpResponse.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        return serverHttpResponse.writeWith(Mono.just(dataBuffer))
                .doOnTerminate(MDC::clear);
    }

    @SuppressWarnings("rawtypes")
    protected Object prepareResponse(ServerWebExchange exchange, Throwable ex){

        ResponseData response;
        if(ex instanceof KycRestException kycRestException){

            response = ResponseData.<Void>builder()
                    .error(kycRestException.getErrorData())
                    .httpStatus(kycRestException.getStatus()).build();
        }
        else{

            response =  ResponseData.<Void>builder()
                    .error(kycMessages.getMessage(MSG_APP_001))
                    .httpStatus(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
        LOGGER.info("RESPONSE {}",response);

        if(requireEncryptionService.requireEncryption(exchange.getRequest())){

            String encryptedJson = "";
            if(exchange.getRequest().getHeaders().containsHeader(HEADER_SESSION_KEY)){

                String key = rsaCipherFacade.decrypt(exchange.getRequest().getHeaders().getFirst(HEADER_SESSION_KEY));
                SecretKey aesKey = transformAesKey(key);

                String json = jsonMapper.writeValueAsString(response);
                encryptedJson = aes256GcmCipherOperation.encrypt(json,aesKey);
            }
            return new GatewayEncryptData(encryptedJson);
        }
        return response;
    }

    protected HttpStatus prepareHttpStatus(Throwable ex){

        if(ex instanceof KycRestException kycRestException){
            return kycRestException.getStatus();
        }
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
