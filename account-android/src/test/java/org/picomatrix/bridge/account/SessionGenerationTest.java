package org.picomatrix.bridge.account;

import org.junit.Test;
import static org.junit.Assert.*;

public class SessionGenerationTest {
    @Test public void logoutRejectsEarlierAuthorizationAndHandoff() throws Exception {
        SessionGeneration generation=new SessionGeneration();long authorization=generation.current(),handoff=generation.current();
        generation.invalidate();
        assertEquals(-10004,assertThrows(AccountClient.Failure.class,()->generation.check(authorization)).code);
        assertThrows(AccountClient.Failure.class,()->generation.check(handoff));
        generation.check(generation.current());
    }
    @Test public void replacingAccountDoesNotRestoreEarlierGeneration() throws Exception {
        SessionGeneration generation=new SessionGeneration();long first=generation.current();generation.invalidate();long second=generation.current();generation.invalidate();
        assertThrows(AccountClient.Failure.class,()->generation.check(first));assertThrows(AccountClient.Failure.class,()->generation.check(second));
        generation.check(generation.current());
    }
}
