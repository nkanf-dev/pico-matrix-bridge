package org.picomatrix.bridge.account;

/** In-flight work may never resurrect an account after logout or replacement. */
final class SessionGeneration {
    private long value;
    long current() { return value; }
    void invalidate() { value++; }
    void check(long expected) throws AccountClient.Failure {
        if(expected!=value) throw new AccountClient.Failure(-10004,"请重新登录");
    }
}
