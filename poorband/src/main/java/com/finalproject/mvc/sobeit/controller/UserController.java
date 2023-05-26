package com.finalproject.mvc.sobeit.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.finalproject.mvc.sobeit.dto.*;
import com.finalproject.mvc.sobeit.entity.Users;
import com.finalproject.mvc.sobeit.service.SmsService;
import com.finalproject.mvc.sobeit.security.TokenProvider;
import com.finalproject.mvc.sobeit.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Random;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class UserController {
    private final UserService userService;

    private final SmsService smsService;

    private final TokenProvider tokenProvider;

    private final Map<String, String> smsMap;

    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody UserDTO userDTO) {
        try {
            // 요청을 이용해 저장할 사용자 만들기
            Users user = Users.builder()
                    .userId(userDTO.getUser_id()) // 사용자 아이디
                    .email(userDTO.getEmail()) // 사용자 이메일
                    .userName(userDTO.getUser_name()) // 사용자 이름
                    .password(passwordEncoder.encode(userDTO.getPassword())) // 사용자 비밀번호
                    .nickname(userDTO.getNickname()) // 사용자 닉네임
                    .phoneNumber(userDTO.getPhone_number()) // 사용자 전화번호
                    .build();

            // 서비스를 이용해 리포지터리에 사용자 저장
            Users registeredUser = userService.create(user);
            UserDTO responseUserDTO = UserDTO.builder()
                    .user_seq(registeredUser.getUserSeq()) // 사용자 고유 번호
                    .user_id(registeredUser.getUserId()) // 사용자 아이디
                    .email(registeredUser.getEmail()) // 사용자 이메일
                    .introduction(registeredUser.getIntroduction()) // 사용자 한 줄 소개
                    .user_name(registeredUser.getUserName()) // 사용자 이름
                    .nickname(registeredUser.getNickname()) // 사용자 닉네임
                    .user_tier(registeredUser.getUserTier()) // 사용자 티어
                    .challenge_count(registeredUser.getChallengeCount()) // 사용자가 완료한 도전 과제 개수
                    .phone_number(registeredUser.getPhoneNumber()) // 사용자 전화번호
                    .profile_image_url(registeredUser.getProfileImageUrl()) // 사용자 프로필 이미지 URL
                    .build();

            // 사용자 정보는 항상 하나이므로 리스트로 만들어야 하는 ResponseDTO를 사용하지 않고 그냥 UserDTO 리턴
            return ResponseEntity.ok().body(responseUserDTO);
        }
        catch (Exception e) {
            ResponseDTO responseDTO = ResponseDTO.builder().error(e.getMessage()).build();

            return ResponseEntity
                    .internalServerError() // Error 500
                    .body(responseDTO);
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticate(@RequestBody UserDTO userDTO) {
        Users user = userService.getByCredentials(
                userDTO.getUser_id(),
                userDTO.getPassword(),
                passwordEncoder);

        if(user != null) {
            // 토큰 생성
            final String token = tokenProvider.create(user);

            final UserDTO responseUserDTO = UserDTO.builder()
                    .user_seq(user.getUserSeq())
                    .user_id(user.getUserId())
                    .email(user.getEmail())
                    .introduction(user.getIntroduction())
                    .user_name(user.getUserName())
                    .nickname(user.getNickname())
                    .user_tier(user.getUserTier())
                    .challenge_count(user.getChallengeCount())
                    .phone_number(user.getPhoneNumber())
                    .profile_image_url(user.getProfileImageUrl())
                    .token(token)
                    .build();

            return ResponseEntity.ok().body(responseUserDTO);
        }
        else {
            ResponseDTO responseDTO = ResponseDTO.builder()
                    .error("Login failed.")
                    .build();

            return ResponseEntity
                    .internalServerError()
                    .body(responseDTO);
        }
    }

    @PostMapping("/signout")
    public ResponseEntity<?> signOut(@AuthenticationPrincipal Users user) {
        if (user != null) {
            return ResponseEntity.ok().body("Logout Succeed.");
        }
        else {
            ResponseDTO responseDTO = ResponseDTO.builder()
                    .error("Logout failed.")
                    .build();

            return ResponseEntity
                    .internalServerError()
                    .body(responseDTO);
        }
    }

    /**
     * @param userDTO : 사용자가 입력한 사용자 아이디
     * @return - 사용자가 입력한 사용자 아이디가 존재하지 않을 경우 : { "is_id_verified": true }
     * @return - 사용자가 입력한 사용자 아이디가 존재할 경우 : 500 Error
     */
    @PostMapping("/checkid")
    public ResponseEntity<?> checkUserId(@RequestBody UserDTO userDTO) {
        Boolean isUserIdVerified = userService.checkUserId(userDTO.getUser_id());

        if (isUserIdVerified) {
            UserDTO responseUserDTO = UserDTO.builder()
                    .is_id_verified(true)
                    .build();
            return ResponseEntity.ok().body(responseUserDTO);
        }
        else {
            ResponseDTO responseCheckUserIdDTO = ResponseDTO.builder()
                    .error("아이디가 중복됩니다.")
                    .build();

            return ResponseEntity
                    .internalServerError()
                    .body(responseCheckUserIdDTO);
        }
    }

    /**
     * @param findIdDTO : 유저가 입력한 이름, 핸드폰 번호
     * @return null일 경우 : 500으로 응답해주고 에러리스폰스 보내주기
     * @return null 아닐 경우 : JSON으로 { "userId" : userId } 보내주기
     */
    @PostMapping("/findid")
    public ResponseEntity<?> findUserId(@RequestBody FindIdDTO findIdDTO) {
        Users findUser = userService.findUserId(findIdDTO.getInputUserName(), findIdDTO.getInputUserPhoneNumber());
        if (findUser != null) {
            String userId = findUser.getUserId();
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("userId", userId);
            return ResponseEntity.ok().body(jsonObject);
        }
        else{
            ResponseDTO responseDTO = ResponseDTO.builder()
                    .error("해당하는 사용자 정보를 찾을 수 없습니다.")
                    .build();

            return ResponseEntity
                    .internalServerError()
                    .body(responseDTO);
        }
    }

    /**
     *
     * @param findPasswordDTO : 유저가 입력한 아이디와 핸드폰 번호
     * @return : 입력받은 정보를 기반으로 User를 찾아서 성공적으로 SMS를 보내면 200 리턴
     *
     */
    @PostMapping("/findpassword")
    public ResponseEntity<?> findUserPassword(@RequestBody FindPasswordDTO findPasswordDTO) throws UnsupportedEncodingException, URISyntaxException, NoSuchAlgorithmException, InvalidKeyException, JsonProcessingException {
        MessageDTO messageDTO = new MessageDTO();
        String phoneNumber = findPasswordDTO.getPhoneNumber();
        String userName = findPasswordDTO.getUserName();

        Users findUser = userService.findUserId(userName, phoneNumber);


        if (findUser != null) {
            messageDTO = new MessageDTO();
            Random rand = new Random();
            String numStr = "";
            for (int i = 0; i < 6; i++) {
                String ran = Integer.toString(rand.nextInt(10));
                numStr += ran;
            }

            messageDTO.setContent("Sobe-it 인증번호는 [" + numStr + "] 입니다.");
            messageDTO.setTo(phoneNumber);
            smsService.sendSms(messageDTO);

            smsMap.put(phoneNumber,numStr);
            System.out.println(smsMap);

            return ResponseEntity.ok().build();
        }
        else{
            ResponseDTO responseDTO = ResponseDTO.builder()
                    .error("해당하는 사용자 정보를 찾을 수 없습니다.")
                    .build();

            return ResponseEntity
                    .internalServerError()
                    .body(responseDTO);
        }
    }

    @PostMapping("/updatePassword")
    public ResponseEntity<?> updatePassword(@RequestBody UpdatePasswordRequestDTO requestDTO) {
        String userName = requestDTO.getUserName();
        String phoneNumber = requestDTO.getPhoneNumber();
        String newPassword = requestDTO.getNewPassword();

        Users findUser = userService.findUserId(userName, phoneNumber);

//        if (findUser != null) {
//        }
        return ResponseEntity.ok().build();
    }
}
