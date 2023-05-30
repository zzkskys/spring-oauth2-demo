package cn.zzkskys.security.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession
import org.springframework.session.web.http.HeaderHttpSessionIdResolver
import org.springframework.session.web.http.HttpSessionIdResolver

@Configuration
@EnableRedisHttpSession
class SessionConfig {
    @Bean
    fun httpSessionIdResolver(): HttpSessionIdResolver {
        return HeaderHttpSessionIdResolver.xAuthToken()
    }
}