package org.picomatrix.bridge.account;

import java.io.*;

final class AccountIo {
    static byte[] read(InputStream in,int limit) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int count;
        while((count=in.read(buffer))!=-1) {
            if(count>limit-out.size()) throw new IOException("Account input too large");
            out.write(buffer,0,count);
        }
        return out.toByteArray();
    }
    private AccountIo() {}
}
