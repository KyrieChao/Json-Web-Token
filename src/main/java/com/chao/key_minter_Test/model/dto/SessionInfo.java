package com.chao.key_minter_Test.model.dto;

import com.chao.key_minter_Test.model.vo.UserVO;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SessionInfo implements Serializable {
    private String id;
    private UserVO key;
    private Instant expires;
    @Serial
    private static final long serialVersionUID = 1L;
}
