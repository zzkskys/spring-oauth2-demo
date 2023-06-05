package cn.zzkskys.security.config

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.savedrequest.RequestCache
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class RestAuthenticationSuccessHandler(
    private val objectMapper: ObjectMapper
) : SimpleUrlAuthenticationSuccessHandler() {

    private var requestCache: RequestCache = HttpSessionRequestCache()

    @Throws(IOException::class)
    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {

        val savedRequest = requestCache.getRequest(request, response)
        if (savedRequest == null) {
            clearAuthenticationAttributes(request)
        }
        setResponse(request, response, authentication)
    }

    private fun setResponse(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        clearAuthenticationAttributes(request)
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        val outputStream = response.outputStream


        val principal = authentication.principal
        objectMapper.writeValue(response.outputStream, principal)
        outputStream.flush()
    }
}