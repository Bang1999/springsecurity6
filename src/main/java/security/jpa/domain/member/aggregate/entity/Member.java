package security.jpa.domain.member.aggregate.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="MEMBER")
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="MEMBER_ID")
    private Long memberId;

    @NotNull
    @Column(name="MEMBER_LOGIN_ID")
    private String loginId;

    @NotNull
    @Column(name="MEMBER_PASSWORD")
    private String password;

    @NotNull
    @Column(name="MEMBER_NAME")
    private String name;

    @Column(name="MEMBER_ROLE")
    private String role;

    @NotNull
    @Column(name="MEMBER_AGE")
    private String age;

    @NotNull
    @Column(name="MEMBER_GENDER")
    private String gender;
}
