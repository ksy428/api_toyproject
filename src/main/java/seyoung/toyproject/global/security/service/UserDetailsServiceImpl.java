package seyoung.toyproject.global.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import seyoung.toyproject.domain.member.Member;
import seyoung.toyproject.domain.member.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByUserId(username).orElseThrow(() -> new UsernameNotFoundException("아이디가 없습니다"));

        return User.builder().username(member.getUserId())
                .password(member.getPassword())
                .roles(member.getRole().name())
                .build();
    }
}
