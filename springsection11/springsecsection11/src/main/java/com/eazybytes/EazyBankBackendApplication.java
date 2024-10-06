package com.eazybytes;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
//@EnableWebSecurity(debug=true)
public class EazyBankBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(EazyBankBackendApplication.class, args);
    }

}
