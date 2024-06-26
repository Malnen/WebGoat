package org.owasp.webgoat.container.lessons;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Handler which sets the correct schema for the currently bound user. This way users are not
 * seeing each other's data, and we can reset data for just one particular user.
 */
public class LessonConnectionInvocationHandler implements InvocationHandler {

    private final Connection targetConnection;

    public LessonConnectionInvocationHandler(Connection targetConnection) {
        this.targetConnection = targetConnection;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof WebGoatUser) {
            WebGoatUser user = (WebGoatUser) authentication.getPrincipal();
            try (var statement = targetConnection.prepareStatement("SET SCHEMA ?")) {
                statement.setString(1, user.getUsername());
                statement.execute();
            }
        }
        try {
            return method.invoke(targetConnection, args);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }
}
