package cn.zzkskys.auth.client

import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.function.client.WebClient


@RestController
class ArticlesController(
    private val webClient: WebClient
) {

}