package org.owasp.webgoat.container.users;

import lombok.AllArgsConstructor;
import org.flywaydb.core.Flyway;
import org.owasp.webgoat.container.lessons.Initializeable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import java.util.function.Function;

/**
 * @author nbaars
 * @since 3/19/17.
 */
@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {
    private static Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final UserTrackerRepository userTrackerRepository;
    private final JdbcTemplate jdbcTemplate;
    private final Function<String, Flyway> flywayLessons;
    private final List<Initializeable> lessonInitializables;

    @Override
    public WebGoatUser loadUserByUsername(String username) throws UsernameNotFoundException {
        WebGoatUser webGoatUser = userRepository.findByUsername(username);
        if (webGoatUser == null) {
            throw new UsernameNotFoundException("User not found");
        } else {
            webGoatUser.createUser();
            lessonInitializables.forEach(l -> l.initialize(webGoatUser));
        }
        return webGoatUser;
    }

    public void addUser(String username, String password) {
        // get user if there exists one by the name
        var userAlreadyExists = userRepository.existsByUsername(username);
        var webGoatUser = userRepository.save(new WebGoatUser(username, password));

        if (!userAlreadyExists) {
            userTrackerRepository.save(
                    new UserTracker(username)); // if user previously existed it will not get another tracker
            createLessonsForUser(webGoatUser);
        }
    }

    private void createLessonsForUser(WebGoatUser webGoatUser) {
        try (Connection connection = jdbcTemplate.getDataSource().getConnection()) {
            String schemaCreationQuery = "CREATE SCHEMA IF NOT EXISTS ? AUTHORIZATION dba";
            try (PreparedStatement statement = connection.prepareStatement(schemaCreationQuery)) {
                statement.setString(1, webGoatUser.getUsername());
                statement.execute();
            }

            flywayLessons.apply(webGoatUser.getUsername()).migrate();
        } catch (SQLException e) {
            logger.error("An exception occurred!", e);  // Handle the exception according to your application's error handling strategy
        }
    }

    public List<WebGoatUser> getAllUsers() {
        return userRepository.findAll();
    }
}
