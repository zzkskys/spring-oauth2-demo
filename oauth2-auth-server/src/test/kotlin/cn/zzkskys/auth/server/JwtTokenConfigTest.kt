package cn.zzkskys.auth.server

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Import
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.test.context.junit.jupiter.SpringExtension
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@ExtendWith(SpringExtension::class)
@Import(JwtTokenConfig::class)
class JwtTokenConfigTest {

    @Autowired
    lateinit var decoder: JwtDecoder

    @Test
    fun keyTest() {
        val key = JwtTokenConfig.generateRsaKey()
        val pubKey = key.public as RSAPublicKey
        val prvKey = key.private as RSAPrivateKey

        val base64PubKey: String = Base64.getEncoder().encodeToString(pubKey.encoded)
        val base64PrvKey: String = Base64.getEncoder().encodeToString(prvKey.encoded)
        println(base64PubKey)
        println(base64PrvKey)
    }
}