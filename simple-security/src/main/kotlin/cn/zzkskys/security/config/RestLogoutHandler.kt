package cn.zzkskys.security.config

import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class RestLogoutHandler : LogoutSuccessHandler {


    override fun onLogoutSuccess(
            request: HttpServletRequest,
            response: HttpServletResponse,
            authentication: Authentication?
    ) {
        response.status = AuthResponse.LOGOUT.code
        response.contentType = MediaType.APPLICATION_JSON_VALUE

        if (request.session != null) {
            request.session.invalidate()
        }
    }
}