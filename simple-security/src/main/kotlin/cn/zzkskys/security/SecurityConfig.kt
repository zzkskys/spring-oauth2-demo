package cn.zzkskys.security

import cn.zzkskys.security.config.RestAuthenticationSuccessHandler
import cn.zzkskys.security.config.RestLogoutHandler
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.AccessDeniedHandlerImpl
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import java.util.Collections.singletonList

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
class SecurityConfig(
        private val objectMapper: ObjectMapper
) {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
                .cors { it.configurationSource(corsConfigurationSource()) }
                .csrf().disable()
                .headers { it.frameOptions().disable() }
                .exceptionHandling { handler ->
                    handler.authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                            .accessDeniedHandler(AccessDeniedHandlerImpl())
                }
                .authorizeHttpRequests {
                    it.antMatchers("/public/**").permitAll()
                    it.anyRequest().authenticated()
                }
                .formLogin { login ->
                    login
                            .loginProcessingUrl("/login")
                            .successHandler(RestAuthenticationSuccessHandler(objectMapper))
                            .failureHandler(SimpleUrlAuthenticationFailureHandler())

                }
                .sessionManagement { it.maximumSessions(1)}
                .logout { logout -> logout.logoutSuccessHandler(RestLogoutHandler()) }

        return http.build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder()
    }

    @Bean
    fun userDetailService(): UserDetailsService {
        val encoder = passwordEncoder()
        val service = InMemoryUserDetailsManager()
        service.createUser(User.withUsername("admin").password(encoder.encode("test")).authorities("a", "b").build())
        return service
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOrigins = singletonList("*")
        configuration.allowedMethods = singletonList("*")
        configuration.allowedHeaders = singletonList("*")
        configuration.allowCredentials = true
        configuration.addExposedHeader("X-Auth-Token")
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }
}