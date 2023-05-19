package cn.zzkskys.resource.server

import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.web.SecurityFilterChain


@EnableWebSecurity
class ResourceServerConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain{
        http.mvcMatcher("/articles/**")
            .authorizeRequests()
            .mvcMatchers("/articles/**")
            .access("hasAuthority('SCOPE_message.read')")
            .and()
            .oauth2ResourceServer()
            .jwt()
        return http.build()
    }

//    /**
//     * 认证成功后可能需要使用内部权限,则可通过该服务提权。
//     */
//    @Bean
//    fun jwtAuthenticationConverter(): JwtAuthenticationConverter {
//        val grantedAuthoritiesConverter = JwtGrantedAuthoritiesConverter()
//        grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities")
//
//        val converter = JwtAuthenticationConverter()
//        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter)
//        return converter
//    }
}