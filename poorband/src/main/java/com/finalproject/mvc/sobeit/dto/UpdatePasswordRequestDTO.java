package com.finalproject.mvc.sobeit.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UpdatePasswordRequestDTO {
    private String userName;
    private String phoneNumber;
    private String newPassword;
}
