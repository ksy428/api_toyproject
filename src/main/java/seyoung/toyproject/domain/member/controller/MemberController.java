package seyoung.toyproject.domain.member.controller;


import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import seyoung.toyproject.domain.member.service.MemberService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @GetMapping("/member/{id}")
    public ResponseEntity getInfo(@PathVariable("id") Long userId){

        Map<String, Object> map = new HashMap<>();
        map.put("id", "test");
        map.put("name", "테스트");
        return new ResponseEntity(map, HttpStatus.OK);
    }


}
