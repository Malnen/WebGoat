package org.owasp.webgoat.lessons.deserialization;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.Base64;

import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InsecureDeserializationTask extends AssignmentEndpoint {

    @PostMapping("/InsecureDeserialization/task")
    @ResponseBody
    public AttackResult completed(@RequestParam String token) {
        String b64token = token.replace('-', '+').replace('_', '/');
        ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(b64token));
        long before, after;
        int delay;

        try (ObjectInputStream ois = new ObjectInputStream(bais)) {
            ois.setObjectInputFilter(filterInfo -> {
                if (filterInfo.serialClass() != null) {
                    return filterInfo.serialClass().equals(VulnerableTaskHolder.class) ?
                            ObjectInputFilter.Status.ALLOWED : ObjectInputFilter.Status.REJECTED;
                }
                return ObjectInputFilter.Status.UNDECIDED;
            });

            before = System.currentTimeMillis(); // Start time before deserialization
            Object o = ois.readObject();
            after = System.currentTimeMillis(); // End time after deserialization

            delay = (int) (after - before); // Calculate the delay in deserialization

            if (!(o instanceof VulnerableTaskHolder)) {
                return failed(this).feedback("insecure-deserialization.wrongobject").build();
            }

            // Use delay to make a decision about the result
            if (delay > 7000) {
                return failed(this).feedback("insecure-deserialization.timeout").build();
            }
            if (delay < 3000) {
                return failed(this).feedback("insecure-deserialization.toofast").build();
            }

            return success(this).build();
        } catch (ClassNotFoundException | IOException e) {
            return failed(this).feedback("insecure-deserialization.error").output(e.getMessage()).build();
        }
    }
}
