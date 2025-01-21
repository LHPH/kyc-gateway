package com.kyc.gateway.model;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class GraphqlRestReq {

    private String operationName;
    private String query;
}
