package cn.zzkskys.security.web

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RequestMapping("/hello")
@RestController
class HelloController {

    @GetMapping
    fun hello() = "Hello World"
}