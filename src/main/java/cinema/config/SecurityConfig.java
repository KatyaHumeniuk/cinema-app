package cinema.config;

import cinema.jwt.JwtConfigurer;
import cinema.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public SecurityConfig(UserDetailsService userDetailsService,
                          PasswordEncoder passwordEncoder,
                          JwtTokenProvider jwtTokenProvider) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .antMatchers(HttpMethod.POST,"/register").permitAll()
                .antMatchers(HttpMethod.GET,"/cinema-halls").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.POST,"/cinema-halls").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET,"/movies").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.POST,"/movies").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET,"/movie-sessions/available").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.POST,"/movie-sessions").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT,"/movie-sessions/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE,"/movie-sessions/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET,"/orders").hasAnyRole("USER")
                .antMatchers(HttpMethod.POST,"/orders/complete").hasRole("USER")
                .antMatchers(HttpMethod.PUT,"/shopping-carts/movie-sessions").hasAnyRole("USER")
                .antMatchers(HttpMethod.GET,"/shopping-carts/by-user").hasRole("USER")
                .antMatchers(HttpMethod.GET,"/users/by-email").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .apply(new JwtConfigurer(jwtTokenProvider))
                .and()
                .headers().frameOptions().disable();
    }
}
