package com.example.jacopo.socket;

import java.security.SecureRandom;

public class IVGen {

    private byte[] iv;

    public IVGen(){
        this.iv=new SecureRandom().generateSeed(32);
    }

    public byte[] getIv() {
        return iv;
    }
}
