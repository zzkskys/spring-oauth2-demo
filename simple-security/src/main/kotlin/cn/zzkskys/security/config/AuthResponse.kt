package cn.zzkskys.security.config

import javax.servlet.http.HttpServletResponse.*

data class AuthResponse(
    val code: Int,
    val message: String
) {
    companion object {

        val WITHOUT_AUTH = AuthResponse(SC_UNAUTHORIZED, "用户未认证或认证已过期")

        val ERROR_AUTH = AuthResponse(SC_BAD_REQUEST, "用户名或密码错误")

        val LOGOUT = AuthResponse(SC_OK,"用户退出成功")

        val NO_AUTHORITY = AuthResponse(SC_FORBIDDEN, "权限不足")
    }
}