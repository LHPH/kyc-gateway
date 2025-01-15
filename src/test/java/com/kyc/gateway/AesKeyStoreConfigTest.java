package com.kyc.gateway;

import com.kyc.core.config.AesKeyStoreConfig;
import com.kyc.core.security.Aes256GcmCipherOperation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ActiveProfiles("test")
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
@Import(value = {AesKeyStoreConfig.class})
public class AesKeyStoreConfigTest {

    @Autowired
    private Aes256GcmCipherOperation aesOperation;

    @Test
    public void encryptString(){

        //String text = "{\"key\": \"test\",\"value\": \"test2\"}";
        String text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI1IiwiYXVkIjoiaHR0cDpcL1wvbG9jYWxob3N0OjkwMDQiLCJyb2xlIjoiQ1VTVE9NRVIiLCJpc3MiOiJLWUNfVVNFUlMiLCJjaGFubmVsIjoiMyIsImtleSI6ImMzMWFjNjE2LThlYzUtNGIzYy05OTc5LTNiZTUzNjk1YWNlYiJ9.HhUQ-yPE6BRicW4B_NF_vPaXLegzep_lXw2oRexfizY";
        String result = aesOperation.encrypt(text);
        System.out.println(result);
        String original = aesOperation.decrypt(result);
        System.out.println(original);
    }

}
