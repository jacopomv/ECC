package com.example.jacopo.socket;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Test {

    private byte[] iv;

    public Test(){
        this.iv=new SecureRandom().generateSeed(32);
        System.out.println("SONO QUI");
        //this.iv = "foss35bche747f7h".getBytes();


    }
    //public static byte[] iv = "foss35bche747f7h".getBytes();
    //public  final byte[] iv = new SecureRandom().generateSeed(32);


    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }
}
