package cn.zzkskys.resource.server

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController


@RestController
class ArticleController {

    @GetMapping("/articles")
    fun getArticles(auth: JwtAuthenticationToken?): Array<String> {
        println(auth)
        return arrayOf("Article 1", "Article 2", "Article 3")
    }

    //当访问不需要认证的接口时,则 auth 失效
    @GetMapping("/users/auth")
    fun auth(auth: JwtAuthenticationToken?): Authentication? {
        return auth
    }
}