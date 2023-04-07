package cn.zzkskys.security

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SimpleSecurityApplication


fun main(args: Array<String>) {
    runApplication<SimpleSecurityApplication>(*args)
}