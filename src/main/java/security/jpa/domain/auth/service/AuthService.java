package security.jpa.domain.auth.service;

import security.jpa.domain.auth.aggregate.dto.SigninDTO;
import security.jpa.domain.auth.aggregate.dto.SignupDTO;

public interface AuthService {
    void signup(SignupDTO signupDTO);

    String signin(SigninDTO signinDTO);
}
