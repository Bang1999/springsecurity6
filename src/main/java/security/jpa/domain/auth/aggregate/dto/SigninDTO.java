package security.jpa.domain.auth.aggregate.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SigninDTO {
    private String loginId;
    private String password;
}
