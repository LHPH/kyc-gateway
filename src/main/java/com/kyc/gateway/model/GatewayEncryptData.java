package com.kyc.gateway.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class GatewayEncryptData {

    @JsonInclude(Include.NON_NULL)
    private String key;
    private String data;

    public GatewayEncryptData(String data){
        this.data = data;
    }
}
