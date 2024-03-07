package seyoung.toyproject.domain.member.service;


import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import seyoung.toyproject.domain.member.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
}
