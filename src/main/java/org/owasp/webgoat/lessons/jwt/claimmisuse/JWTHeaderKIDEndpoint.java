package org.owasp.webgoat.lessons.jwt.claimmisuse;

import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.TextCodec;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.*;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@RestController
@AssignmentHints({
        "jwt-kid-hint1",
        "jwt-kid-hint2",
        "jwt-kid-hint3",
        "jwt-kid-hint4",
        "jwt-kid-hint5",
        "jwt-kid-hint6"
})
@RequestMapping("/JWT/kid")
public class JWTHeaderKIDEndpoint extends AssignmentEndpoint {

    private final LessonDataSource dataSource;

    private JWTHeaderKIDEndpoint(LessonDataSource dataSource) {
        this.dataSource = dataSource;
    }

    @PostMapping("/follow/{user}")
    public @ResponseBody
    String follow(@PathVariable("user") String user) {
        if ("Jerry".equals(user)) {
            return "Following yourself seems redundant";
        } else {
            return "You are now following Tom";
        }
    }

    @PostMapping("/delete")
    public @ResponseBody
    AttackResult resetVotes(@RequestParam("token") String token) {
        if (StringUtils.isEmpty(token)) {
            return failed(this).feedback("jwt-invalid-token").build();
        } else {
            try {
                final String[] errorMessage = {null};
                Jwt jwt =
                        Jwts.parser()
                                .setSigningKeyResolver(
                                        new SigningKeyResolverAdapter() {
                                            @Override
                                            public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                                                final String kid = (String) header.get("kid");
                                                try (Connection connection = dataSource.getConnection()) {
                                                    String query = "SELECT key FROM jwt_keys WHERE id = ?";
                                                    try (PreparedStatement statement = connection.prepareStatement(query)) {
                                                        statement.setString(1, kid);
                                                        ResultSet rs = statement.executeQuery();
                                                        while (rs.next()) {
                                                            return TextCodec.BASE64.decode(rs.getString(1));
                                                        }
                                                    }
                                                } catch (SQLException e) {
                                                    errorMessage[0] = e.getMessage();
                                                }
                                                return null;
                                            }
                                        })
                                .parseClaimsJws(token);
                if (errorMessage[0] != null) {
                    return failed(this).output(errorMessage[0]).build();
                }
                Claims claims = (Claims) jwt.getBody();
                String username = (String) claims.get("username");
                if ("Jerry".equals(username)) {
                    return failed(this).feedback("jwt-final-jerry-account").build();
                }
                if ("Tom".equals(username)) {
                    return success(this).build();
                } else {
                    return failed(this).feedback("jwt-final-not-tom").build();
                }
            } catch (JwtException e) {
                return failed(this).feedback("jwt-invalid-token").output(e.toString()).build();
            }
        }
    }
}
