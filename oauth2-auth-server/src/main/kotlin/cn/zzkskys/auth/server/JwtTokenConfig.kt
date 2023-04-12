package cn.zzkskys.auth.server

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


@Configuration
class JwtTokenConfig {

    companion object {
        /**
         * 生成秘钥对，为jwkSource提供服务。
         * @return
         */
        fun generateRsaKey(): KeyPair {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            return keyPairGenerator.generateKeyPair()
        }
    }

    /**
     * 用于给access_token签名使用。
     * @return
     */
    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair = generateRsaKey()
        val pubKey = keyPair.public as RSAPublicKey
        val prvKey = keyPair.private as RSAPrivateKey
        val rsaKey = RSAKey.Builder(pubKey)
            .privateKey(prvKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet = JWKSet(rsaKey)

        val base64PubKey: String = Base64.getEncoder().encodeToString(pubKey.encoded)
        val base64PrvKey: String = Base64.getEncoder().encodeToString(prvKey.encoded)

        println("pubKey : $base64PubKey")
        println("prvKey : $base64PrvKey")
        return ImmutableJWKSet(jwkSet)
    }


    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    /**
     * 定制 access_token
     */
    @Bean
    fun accessTokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer { context ->
            val authentication = context.getPrincipal() as Authentication?
            if (authentication != null) {
                context.claims.claim("username", authentication.name)
            }
        }
    }
}