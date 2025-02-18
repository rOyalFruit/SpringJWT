package com.ll.backend.controller;

import com.ll.backend.dto.JoinDto;
import com.ll.backend.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(JoinDto joinDto) {

        System.out.println(joinDto.getUsername());
        joinService.joinProcess(joinDto);

        return "ok";
    }
}
