import java.security.*;
import java.io.*;
import java.security.cert.*;
import java.security.cert.Certificate;


public class X509 {
	private static boolean judge = false;
	
	public static void main(String[] args) throws IOException {
		
		String fileLocation = "resource/github.com.cer";
		if(args.length > 0) {
			System.out.println(args[0]);
			fileLocation = args[0];
		}
		
		try {
			// 获取工厂实例
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // 用文件流读入证书
			FileInputStream fis = new FileInputStream(fileLocation);
			// 生成证书
		    Certificate c = cf.generateCertificate(fis);
		    X509Certificate t = (X509Certificate)c;
		    fis.close();
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
		    System.out.println("签名算法: " + t.getSigAlgName());
		    System.out.println("签名: " + t.getSignature().toString());
		    System.out.println("公钥: ");
		    PublicKey pk = t.getPublicKey();
		    String pkStr = pk.toString();
		    String[] pkInfo = pkStr.split("\n");
		    for(int i = 0; i < pkInfo.length; i++) 
		    	System.out.println("    " + pkInfo[i].trim());
		} catch (CertificateException e) {
			System.out.println("Read " + fileLocation + " failed! ");
		} catch (FileNotFoundException e) {
			System.out.println("No such file: " + fileLocation);
		}
	}
}