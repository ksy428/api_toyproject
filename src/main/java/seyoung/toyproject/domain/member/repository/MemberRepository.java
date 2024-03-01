package seyoung.toyproject.domain.member.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import seyoung.toyproject.domain.member.Member;

import java.util.Optional;


public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByUserId(String userId);
}
