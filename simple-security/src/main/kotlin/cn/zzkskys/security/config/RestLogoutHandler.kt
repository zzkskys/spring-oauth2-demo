package cn.zzkskys.security.config

import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.savedrequest.RequestCache
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class RestLogoutHandler : LogoutSuccessHandler {

    private var requestCache: RequestCache = HttpSessionRequestCache()

    override fun onLogoutSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication?
    ) {
        response.status = AuthResponse.LOGOUT.code
        response.contentType = MediaType.APPLICATION_JSON_VALUE

        val session = request.getSession(false)
//        request.requestedSessionId
        if (session != null) {
            session.invalidate()
        }
    }
}