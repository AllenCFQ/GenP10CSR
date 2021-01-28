package com.allen;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * CSR 生成工具类
 * 生成国密算法的P10格式的CSR文件
 * add by 2021-01-28 18:48:17
 */
public class GenP10_3_git2 {


    static String filepath = "c:\\Users\\12804\\Desktop\\SVN\\004_中国银联\\202009银联刷脸支付\\002开发\\密钥证书\\";

    public static void main(String[] args) throws OperatorCreationException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        //write("c:\\Users\\12804\\Desktop\\SVN\\004_中国银联\\202009银联刷脸支付\\002开发\\密钥证书\\","123","123".getBytes());
        String p10Base64 = generateCsr(false);
    }

    /**
     * 算法提供者 Bouncy Castle
     */
    private static final Provider BC = new BouncyCastleProvider();

    /**
     * 生成 PKCS#10 证书请求
     *
     * @param isRsaNotEcc {@code true}：使用 RSA 加密算法；{@code false}：使用 ECC（SM2）加密算法
     * @return RSA P10 证书请求 Base64 字符串
     * @throws NoSuchAlgorithmException  当指定的密钥对算法不支持时
     * @throws InvalidAlgorithmParameterException 当采用的 ECC 算法不适用于该密钥对生成器时
     * @throws OperatorCreationException 当创建签名者对象失败时
     * @throws IOException               当打印 OpenSSL PEM 格式文件字符串失败时
     */
    public static String generateCsr(boolean isRsaNotEcc) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, OperatorCreationException, IOException {


        String dn="CN=xx@oo@xx@3,OU=Organizational-2,OU=oo,O=CFCA ACS OCA31,C=CN";

        System.out.println("DN");
        System.out.println(dn);
        // 使用 RSA/ECC 算法，生成密钥对（公钥、私钥）
        KeyPairGenerator generator = KeyPairGenerator.getInstance(isRsaNotEcc ? "RSA" : "EC", BC);
        if (isRsaNotEcc) {
            // RSA
            generator.initialize(2048);
        } else {
            // ECC
            generator.initialize(new ECGenParameterSpec("sm2p256v1"));
        }
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 打印私钥，注意：请务必保存您的私钥
        printOpensslPemFormatKeyFileContent(privateKey, isRsaNotEcc);


        // 打印公钥
        printOpensslPemFormatKeyFileContent(publicKey, isRsaNotEcc);

        // 按需添加证书主题项，
        // 有些 CSR 不需要我们在主题项中添加各字段,
        // 如 `C=CN, CN=吴仙杰, E=wuxianjiezh@gmail.com, OU=3303..., L=杭州, S=浙江`，
        // 而是通过额外参数提交，故这里我只简单地指定了国家码


        X500Principal subject = new X500Principal(dn);

        // 使用私钥和 SHA256WithRSA/SM3withSM2 算法创建签名者对象
        ContentSigner signer = new JcaContentSignerBuilder(isRsaNotEcc ? "SHA256WithRSA" : "SM3withSM2")
                .setProvider(BC)
                .build(privateKey);

        // 创建 CSR
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
        PKCS10CertificationRequest csr = builder.build(signer);

        String p10Base64 = Base64.getEncoder().encodeToString(csr.getEncoded());
        // 打印 OpenSSL PEM 格式文件字符串
        printOpensslPemFormatCsrFileContent(csr,p10Base64);
        // 以 Base64 字符串形式返回 CSR
        return p10Base64;
    }

    /**
     * 打印 OpenSSL PEM 格式文件字符串的 SSL证书密钥 KEY 文件内容
     *
     * @param privateKey 私钥
     * @param isRsaNotEcc {@code true}：使用 RSA 加密算法；{@code false}：使用 ECC（SM2）加密算法
     */
    private static void printOpensslPemFormatKeyFileContent(PrivateKey privateKey, boolean isRsaNotEcc) throws IOException {

        write(filepath,"p10pri.pri",privateKey.getEncoded());

        PemObject pem = new PemObject(isRsaNotEcc ? "PRIVATE KEY" : "EC PRIVATE KEY", privateKey.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();
        System.out.println("私钥 PEM格式");
        System.out.println(str.toString());
        System.out.println("私钥 BASE64");
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("私钥HEX:"+StringUtil.byte2HexStr(privateKey.getEncoded()));

    }

    private static void printOpensslPemFormatKeyFileContent(PublicKey publicKey, boolean isRsaNotEcc) throws IOException {

        write(filepath,"p10pub.pub",publicKey.getEncoded());
        PemObject pem = new PemObject(isRsaNotEcc ? "PRIVATE KEY" : "EC PRIVATE KEY", publicKey.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();

        System.out.println("公钥 PEM格式");
        System.out.println(str.toString());
        System.out.println("公钥 BASE64");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("公钥HEX:"+StringUtil.byte2HexStr(publicKey.getEncoded()));
    }

    /**
     * 打印 OpenSSL PEM 格式文件字符串的 SSL 证书请求 CSR 文件内容
     *
     * @param csr 证书请求对象
     */
    private static void printOpensslPemFormatCsrFileContent(PKCS10CertificationRequest csr, String p10Base64) throws IOException {
        write(filepath,"p10.csr",csr.getEncoded());

        PemObject pem = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();

        System.out.println("P10 PEM格式");
        System.out.println(str.toString());
        System.out.println("P10 BASE64");
        System.out.println(p10Base64);
    }

    private static void write(String path, String filename , byte[] bytes ) throws IOException {

        File file = new File(path+"/"+filename);
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fop = new FileOutputStream(file);
        fop.write(bytes);
        fop.flush();
        fop.close();
    }
}