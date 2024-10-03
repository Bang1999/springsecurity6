package com.eazybytes.events;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthenticationEvents {

    // 로그인 성공시 발생하는 이벤트
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent successEvent){
        log.info("로그인 성공 유저: {}", successEvent.getAuthentication().getName());
    }

    // 로그인 실패시 발생하는 이벤트
    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent failureEvent){
        log.error("로그인 실패 유저: {} due to: {}", failureEvent.getAuthentication().getName(), failureEvent.getException().getMessage());
    }
}
