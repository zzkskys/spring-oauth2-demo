package cn.zzkskys.security.web

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/public")
class PublicController {

    @GetMapping("/hello")
    fun hello() = "Hello World"
}