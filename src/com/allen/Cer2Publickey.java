package com.allen;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;

/**
 * 从cer中获取公钥信息，包括序列号，dn等信息
 * add by oyp 2021-01-28 18:47:55
 */
public class Cer2Publickey {

    public static void main(String[] args) throws IOException {
        certTest();
    }

    public static  void certTest() throws IOException {

//        String privateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgTchUuHEAckzfS16v\n" +
//                "8hz4Rt9G+41OifbzAr9jM+JGxiygCgYIKoEcz1UBgi2hRANCAASDw0oz+lq1H8QM\n" +
//                "8YaZSikOsCdbLR+sUd+hpzvDF1wmS3zVNqtKnTRzD3bVgR4AFljtBVmbXNmJdrno\n" +
//                "C8r6EmyE";

//        String privateKey = "nbXbTHQUGrAzEywesR7Wpcd8D3ZS3wcVpnNdYGph/OU=";
//        byte[] sk = org.bouncycastle.util.encoders.Base64.decode(privateKey);
//        System.out.println("私钥长度" + sk.length);
//        System.out.println(Hex.toHexString(sk));



        //String cert_path = TestSm2.class.getResource("/szca/testsm2.pem").getPath();
        //String cert_path = "C:\\idea-utf8\\PRE\\untitled\\src\\com\\hznu\\4000370700.cer";
        //String cert_path = "C:\\Users\\12804\\Desktop\\SVN\\004_中国银联\\202009银联刷脸支付\\002开发\\密钥证书\\刷脸付业务证书指引及测试证书\\银联证书（测试）\\1-rlsb-cert加密证书（测试）.cer";
        //String cert_path = "c:\\Users\\12804\\Desktop\\SVN\\004_中国银联\\202009银联刷脸支付\\002开发\\密钥证书\\刷脸付业务证书指引及测试证书\\银联证书（测试）\\2-rlsb-cert加密证书（测试）.cer";
        String cert_path = "c:\\Users\\12804\\Desktop\\SVN\\004_中国银联\\202009银联刷脸支付\\006生产\\银联刷脸付证书公钥（生产）-给收单机构\\1-rlsb-cert加密证书.cer";
        //String cert_path = "c:\\Users\\12804\\Desktop\\SVN\\004_中国银联\\202009银联刷脸支付\\005联机测试\\证书信息\\测试验签证书公钥.cer";
        byte[] idBytes = FileUtils.readFileToByteArray(new File(cert_path));

        Certificate certificate = Certificate.getInstance(new PemReader(new InputStreamReader(new ByteArrayInputStream(idBytes))).readPemObject().getContent());
        byte[] publickey = certificate.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();


        System.out.println("dn---:"+certificate.getSubject());
        System.out.println("序列号---："+new BigInteger(certificate.getSerialNumber().toString()).toString(16));
        System.out.println("公钥：" + Hex.toHexString(publickey).toUpperCase());
        System.out.println("公钥长度：" + publickey.length);
        System.out.println("前面的04一般去掉:" + publickey.length);


    }


    private static java.security.cert.Certificate getCertificate(String certificatePath) throws Exception {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            FileInputStream in = new FileInputStream(certificatePath);
            java.security.cert.Certificate certificate = factory.generateCertificate(in);
            in.close();
            return certificate;
        } catch (Exception e) {

           throw  e;
        }
    }



}
