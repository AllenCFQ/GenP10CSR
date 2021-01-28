package com.allen;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * 根据 生成的国密公私钥对 中的私钥
 * 获取到64长度的16进制原始私钥，即256长的的二进制。
 * add by oyp
 */
public class PrivateKey2ECPrivateKey {
    public static void main(String[] args) {
        ECPrivateKey privateKey = (ECPrivateKey) getPrivateKey();
        String b = new BigInteger(privateKey.getS()+"").toString(16);
        System.out.println("原始私钥:"+b.toUpperCase());
    }

    private static PrivateKey getPrivateKey() {
        Security.addProvider(new BouncyCastleProvider());
        PrivateKey privateKey = null;
        //String priKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDyKdsBfK53qUmrZdWvkwvQqmG6mXMMXISNehS7aRN8iQ==";
        String priKey ="MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgZGn1Uzkih5p33Kw+tsU11QFy7AFJWtzjfZ4v5gn7X+6gCgYIKoEcz1UBgi2hRANCAARAs/OVLOQiXz1rFwNvvD5un00bHx965Z4dQlmkX7YwM6g+y8vnmi5eq1xefiY1pJqDIFZ3eZuXsUcU1epadJUS";
        PKCS8EncodedKeySpec priPKCS8;
        try {
            System.out.println("priKey:"+priKey);
            priPKCS8 = new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(priKey));
            KeyFactory keyf = KeyFactory.getInstance("EC");
            privateKey = keyf.generatePrivate(priPKCS8);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }
}
