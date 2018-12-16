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
			// ��ȡ����ʵ��
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // ���ļ�������֤��
			FileInputStream fis = new FileInputStream(fileLocation);
			// ����֤��
		    Certificate c = cf.generateCertificate(fis);
		    X509Certificate t = (X509Certificate)c;
		    fis.close();
		    System.out.println("�汾��: " + t.getVersion());
		    System.out.println("���к�: " + t.getSerialNumber().toString(16));
		    System.out.println("�䷢�߲���: ");
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
		    System.out.println("��Ч��ʼ����: " + t.getNotBefore());
		    System.out.println("��Ч��ֹ����: " + t.getNotAfter());
		    System.out.println("���岿��: ");
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
		    System.out.println("ǩ���㷨: " + t.getSigAlgName());
		    System.out.println("ǩ��: " + t.getSignature().toString());
		    System.out.println("��Կ: ");
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