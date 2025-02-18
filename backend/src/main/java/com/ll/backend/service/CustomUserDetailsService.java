package com.ll.backend.service;

import com.ll.backend.dto.CustomUserDetails;
import com.ll.backend.entity.Member;
import com.ll.backend.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member userData = memberRepository.findByUsername(username);

        if(userData != null) {
            return new CustomUserDetails(userData);
        }

        // 사용자 이름으로 사용자를 찾지 못했을 때 null을 반환하는 대신 UsernameNotFoundException을 던져야 함.
        throw new UsernameNotFoundException("User not found with username: " + username);
    }
}