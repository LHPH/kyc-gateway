package com.kyc.gateway.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyc.core.exception.KycRestException;
import com.kyc.core.properties.KycMessages;
import com.kyc.gateway.model.GraphqlRestReq;
import com.kyc.gateway.rewrites.CustomerGraphqlRestReqRewrite;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyRequestBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.List;

import static com.kyc.gateway.constants.AppConstants.MSG_APP_002;

@Component
public class CustomerQueryGraphqlGatewayFilterFactory extends AbstractGatewayFilterFactory<CustomerQueryGraphqlGatewayFilterFactory.Config> {

    private final static Logger LOGGER = LoggerFactory.getLogger(CustomerQueryGraphqlGatewayFilterFactory.class);
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private ModifyRequestBodyGatewayFilterFactory factory;
    @Autowired
    private KycMessages kycMessages;

    public CustomerQueryGraphqlGatewayFilterFactory(){super(Config.class);}

    @Override
    public GatewayFilter apply(Config config) {
        return new OrderedGatewayFilter((exchange, chain) -> {

            GraphqlRestReq req =  (GraphqlRestReq) exchange.getAttributes().get(ServerWebExchangeUtils.CACHED_REQUEST_BODY_ATTR);
            String sub = exchange.getAttributes().get("sub").toString();

            if(config.getOperation().equals(req.getOperationName())){

                String replacementWithSub = String.format(config.getReplacement(),sub);
                req.setQuery(req.getQuery().replaceFirst(config.getRegex(),replacementWithSub));

                ModifyRequestBodyGatewayFilterFactory.Config cfg = new ModifyRequestBodyGatewayFilterFactory.Config();
                cfg.setRewriteFunction(String.class, String.class, new CustomerGraphqlRestReqRewrite(objectMapper,req));

                GatewayFilter modifyBodyFilter = factory.apply(cfg);

                return modifyBodyFilter.filter(exchange, chain);
            }
            else{
                throw KycRestException.builderRestException()
                        .errorData(kycMessages.getMessage(MSG_APP_002))
                        .status(HttpStatus.FORBIDDEN)
                        .build();
            }
        }, Ordered.LOWEST_PRECEDENCE-1);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("regex","replacement","operation");
    }

    @Getter
    public static class Config {

        private String regex;
        private String replacement;
        private String operation;

        public Config setRegex(String regex) {
            Assert.hasText(regex, "regex must have a value");
            this.regex = regex;
            return this;
        }

        public Config setReplacement(String replacement) {
            Assert.hasText(regex, "replacement must have a value");
            this.replacement = replacement;
            return this;
        }

        public Config setOperation(String operation) {
            Assert.hasText(operation, "operation must have a value");
            this.operation = operation;
            return this;
        }
    }
}
