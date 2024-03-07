package seyoung.toyproject.domain.member;

import jakarta.persistence.*;
import lombok.*;
import seyoung.toyproject.domain.BaseEntity;

@Entity
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class Member extends BaseEntity {

    @Id
    @GeneratedValue(strategy =  GenerationType.IDENTITY)
    @Column
    private Long id;

    @Column(unique = true)
    private String userId;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;
    private String refreshToken;

    public void updateRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }
    public void destroyRefreshToken(){
        this.refreshToken = null;
    }


}
