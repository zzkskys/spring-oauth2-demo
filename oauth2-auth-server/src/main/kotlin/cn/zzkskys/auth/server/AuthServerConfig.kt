package cn.zzkskys.auth.server

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import java.time.Duration
import java.util.*


@Configuration
class AuthServerConfig {
    /**
     * OAuth2AuthorizationServerConfigurer 提供了定制 OAuth2 的认证能力。它提供了以下的扩展点能让你自定义客户端认证
     * 请求的预处理、主要处理和后逻辑处理:
     * 1. 可以从 HttpServletRequest 中提取 OAuth2ClientAuthenticationToken 凭证
     * 2. 传递定制的 AuthenticationProvider 进行认证
     * 3. 传递定制的 AuthenticationSuccessHandler 对认证成功进行预处理
     * 4. 传递定制的 AuthenticationFailureHandler 对认证失败进行预处理，并返回 OAuth2Error 响应
     */
    @Bean
    @Order(1)
    @Throws(Exception::class)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer()
        http
            .apply(authorizationServerConfigurer)
            .oidc(Customizer.withDefaults())

        http
            .requestMatcher(authorizationServerConfigurer.endpointsMatcher)
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .csrf { csrf -> csrf.disable() }
            .exceptionHandling { exceptions ->
                exceptions
                    .authenticationEntryPoint(
                        LoginUrlAuthenticationEntryPoint("/login")
                    )
            }
            .oauth2ResourceServer{server -> server.jwt()}

        return http.build()
    }


    /**
     * oauth2 用于第三方认证，RegisteredClientRepository 主要用于管理第三方（每个第三方就是一个客户端）
     * @return
     */
    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("messaging-client")
            .clientSecret("{noop}secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantTypes {
                it.add(AuthorizationGrantType.AUTHORIZATION_CODE)
                it.add(AuthorizationGrantType.REFRESH_TOKEN)
                it.add(AuthorizationGrantType.CLIENT_CREDENTIALS)
                it.add(AuthorizationGrantType.JWT_BEARER)
            }
            .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
            .redirectUri("http://127.0.0.1:8080/authorized")
            .scope(OidcScopes.OPENID)
            .scope("message.read")
            .scope("message.write")
            .clientSettings(
                ClientSettings
                    .builder()
                    .requireAuthorizationConsent(true)
                    .build()
            )
            .tokenSettings(
                TokenSettings
                    .builder()
                    .accessTokenTimeToLive(Duration.ofHours(1))
                    .refreshTokenTimeToLive(Duration.ofHours(1))
                    .build()
            )
            .build()
        return InMemoryRegisteredClientRepository(registeredClient)
    }


    /**
     * 授权服务器暴露的端点配置。
     * 相关的配置内容就是客户端访问的路径。
     */
    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder().build()
    }

}