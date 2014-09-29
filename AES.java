/*

David Kernan
Cryptography Assignment


59597883


*/
import javax.crypto.*;
import java.security.Security;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.util.Random;
import java.security.*;
import java.util.*;
import javax.xml.bind.DatatypeConverter;

public class AES
{
	public static String toHex(byte[] bytes)
	{
		StringBuilder sb = new StringBuilder(bytes.length);
		for (byte b: bytes ) {
			sb.append(Integer.toHexString(b+0x800).substring(1));
		}
		return sb.toString();
	}

	public static BigInteger mod_pow(BigInteger base, BigInteger exponent, BigInteger modulus)
	{
		BigInteger answer = new BigInteger("1");
		BigInteger zero = new BigInteger("0");
		while (exponent.compareTo(zero) == 1) {
			if (exponent.mod(new BigInteger("2")).compareTo(new BigInteger("1")) == 0) {
				answer = answer.multiply(base).mod(modulus);
			}
			exponent = exponent.shiftRight(1);
			base = base.multiply(base).mod(modulus);
		}

		return answer;
	}

	public static String decrypt(SecretKey pubKey, String ctxt)
	{
		MessageDigest md = null;
		Cipher cipher = null;
		SecretKeySpec key = null;
		String plain = null;


		byte[] msg = DatatypeConverter.parseHexBinary(ctxt);
		try
		{
			cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, pubKey);
			byte[] array = cipher.doFinal(msg);
			plain = new String(Arrays.toString(array));
			plain = plain + "\n";
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}

		return plain;

	}

	public static String encrypt(SecretKey pubKey, byte[] message)
	{
		Cipher cipher = null;
		String hex = null;
		try
		{
			cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);

		}
		catch(Exception e){}

		try
		{
			byte[] b = cipher.doFinal(message);
			hex = toHex(b);
		}
		catch(Exception e){}
		return hex;
	}

	public static void main(String[] args)
	{
		//Init everything
		SecretKey key = null;
		MessageDigest md = null;
		Cipher aes = null;
		Cipher decrypt = null;
		try{
			md = MessageDigest.getInstance("SHA-256");
			aes = Cipher.getInstance("AES");
			decrypt = Cipher.getInstance("AES");
		}
		catch(Exception e){e.printStackTrace();}
		//Keys as Per spec
		String publicKey = "5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d";
		String hexString = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
		String genString = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
		
		//Message
		byte[] zeros = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		//Randomly Generated Private Key
		String privString = "6567FE9F51472ADC1A13FC89083505C2866175FDBB781AC7C996D1D52358FD1A5F274454441621E915F9FA491AD02EBAD140494AC1CB965990C08C7922675BBD6B13DC1EDA52BB194E05AC10A97D3E7B24AD0BE1A32B16F89A17378DADDE5F3F5264E65889710E0BE925CC529F19886014A7360ECEAFA4C4BFF5A89CAE28CB1";

		//Convert strings to BigIntegers
		BigInteger p = new BigInteger(hexString, 16);
		BigInteger g = new BigInteger(genString, 16);
		BigInteger A = new BigInteger(publicKey, 16);
		BigInteger b = new BigInteger(privString, 16);
		BigInteger B = mod_pow(g, b, p);
		BigInteger s = mod_pow(A, b, p);

		System.out.println(toHex(B.toByteArray()));

		//Hashing
		try
		{
			byte[] k = md.digest(s.toByteArray()); // Hash the AES key down to 256 bits
			key = new SecretKeySpec(k, "AES"); //AES-256 bit key.
		}
		catch(Exception e)
		{

		}

		System.out.println("Message = " + Arrays.toString(zeros));
		//Run encrypt() with the key on the 16 byte message
		String encrypted = encrypt(key, zeros); 
		System.out.println("Encrypted = " + encrypted); 
		System.out.print("Decrypted = " + decrypt(key, encrypted));



	}
}
