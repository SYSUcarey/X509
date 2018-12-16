import java.security.*;
import java.io.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Scanner;


public class X509 {
	private static boolean judge = false;
	
	public static void main(String[] args) throws IOException {
		
		String fileLocation = "resource/github.com.cer";
		if(args.length > 0) {
			System.out.println(args[0]);
			fileLocation = args[0];
		}
		
		try {
			CertificateFactory cf;
			 // 获取工厂实例
			cf = CertificateFactory.getInstance("X.509");
            // 用文件流读入证书
			FileInputStream in=new FileInputStream(fileLocation);
			// 生成证书
		    Certificate c=cf.generateCertificate(in);
		    X509Certificate t=(X509Certificate)c;
		    in.close();
		    System.out.println("版本号: " + t.getVersion());
		    System.out.println("序列号: " + t.getSerialNumber().toString(16));
		    System.out.println("颁发者部分: ");
		    String issuerDN = t.getIssuerDN().toString();
		    String[] issuerInfo = issuerDN.split(",");
		    judge = false;
		    for(int i  = 0; i < issuerInfo.length; i++) {
		    	if(issuerInfo[i].contains("\"")) {
		    		if(judge) System.out.println("," + issuerInfo[i]);
		    		else {
		    			int index = issuerInfo[i].indexOf("=");
				    	String key = issuerInfo[i].substring(0, index).replaceAll(" ", "");
				    	String value = issuerInfo[i].substring(index+1);
				    	System.out.print("    [" + key + "]: " + value);
		    		}
		    		judge = !judge;
		    		continue;
		    	}
		    	int index = issuerInfo[i].indexOf("=");
		    	String key = issuerInfo[i].substring(0, index).replaceAll(" ", "");
		    	String value = issuerInfo[i].substring(index+1);
		    	System.out.println("    [" + key + "]: " + value);
		    }
		    System.out.println("有效起始日期: " + t.getNotBefore());
		    System.out.println("有效终止日期: " + t.getNotAfter());
		    System.out.println("主体部分: ");
		    String[] subjectInfo = t.getSubjectDN().toString().split(",");
		    judge =false;
		    for(int i  = 0; i < subjectInfo.length; i++) {
		    	if(subjectInfo[i].contains("\"")) {
		    		if(judge) System.out.println("," + subjectInfo[i]);
		    		else {
		    			int index = subjectInfo[i].indexOf("=");
				    	String key = subjectInfo[i].substring(0, index).replaceAll(" ", "");
				    	String value = subjectInfo[i].substring(index+1);
				    	System.out.print("    [" + key + "]: " + value);
		    		}
		    		judge = !judge;
		    		continue;
		    	}
		    	int index = subjectInfo[i].indexOf("=");
		    	String key = subjectInfo[i].substring(0, index).replaceAll(" ", "");
		    	String value = subjectInfo[i].substring(index+1);
		    	System.out.println("    [" + key + "]: " + value);
		    }
		    System.out.println("签名算法："+t.getSigAlgName());
		    System.out.println("签名："+t.getSignature().toString());
		    PublicKey pk = t.getPublicKey();
		    byte [] pkenc = pk.getEncoded();  
		    System.out.println("公钥:");
		    for(int i = 0; i < pkenc.length; i++) {
		    	System.out.print(String.format("%5d", pkenc[i]));
		    	if(i != pkenc.length-1) System.out.print(",");
		    	if(i%8 == 7) System.out.println();
		    }
		    System.out.println();
		} catch (CertificateException e) {
			System.out.println("Read " + fileLocation + " failed! ");
		} catch (FileNotFoundException e) {
			System.out.println("No such file: " + fileLocation);
		}
	}
}