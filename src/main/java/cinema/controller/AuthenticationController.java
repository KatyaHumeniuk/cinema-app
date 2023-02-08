package cinema.controller;

import cinema.dto.request.UserLoginDto;
import cinema.dto.request.UserRegistrationDto;
import cinema.dto.response.UserResponseDto;
import cinema.exception.AuthenticationException;
import cinema.jwt.JwtTokenProvider;
import cinema.model.User;
import cinema.service.AuthenticationService;
import cinema.service.mapper.ResponseDtoMapper;
import cinema.service.mapper.UserMapper;
import java.util.Map;
import java.util.stream.Collectors;
import javax.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {
    private final AuthenticationService authService;
    private final UserMapper userMapper;
    private final JwtTokenProvider jwtTokenProvider;
    private final ResponseDtoMapper<UserResponseDto, User> userDtoResponseMapper;

    public AuthenticationController(AuthenticationService authService,
                                    UserMapper userMapper,
                                    JwtTokenProvider jwtTokenProvider,
                                    ResponseDtoMapper<UserResponseDto, User>
                                            userDtoResponseMapper) {
        this.authService = authService;
        this.userMapper = userMapper;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDtoResponseMapper = userDtoResponseMapper;
    }

    @PostMapping("/register")
    public UserResponseDto register(@RequestBody @Valid UserRegistrationDto requestDto) {
        User user = authService.register(requestDto.getEmail(), requestDto.getPassword());
        return userDtoResponseMapper.mapToDto(user);
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody @Valid UserLoginDto userLoginDto)
            throws AuthenticationException {
        User user = authService
                .login(userLoginDto.getLogin(), userLoginDto.getPassword());
        String token = jwtTokenProvider.createToken(user.getEmail(),
                user.getRoles().stream()
                        .map(r -> r.getRoleName().name())
                        .collect(Collectors.toSet()));
        return new ResponseEntity<>(Map.of("token", token), HttpStatus.OK);
    }
}
