import java.net.*;
import java.io.*;
import java.lang.Math;
import java.util.*;
import java.math.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;




public class client{
	/* Below are some global variables used in the code.
	   Their functioning can be easily understood by their name.
	*/
	public static boolean encrypt = false;
	public static int[] Sbox = new int[]{0x09,0x04,0x0a,0x0b,0x0d,0x01,0x08,0x05,0x06,0x02,0x00,0x03,0x0c,0x0e,0x0f,0x07};
	public static int[] RoundConstant = new int[]{0x80,0xaa,0x30};
	public static int[][] MixMat = {{1,4},{4,1}};
	public static int key;
	public static int ciph,msg;
	public static int[] skey = new int[]{0,0,0};
	public static int[] w = new int[]{0,0,0,0,0,0};
	public static int[] intArray = new int[]{1,2,3,4,5,6,7,8,9,10};
	public static String Round_0="",Round_1_S_N="",Round_1_S_R="",Round_1_M_C="",Round_1_ARK="",Round_2_S_N="",Round_2_S_R="",Round_2_ARK="";
	public static BigInteger p,q,N,N1,e,e1,d,d1,phi;
	public static BigInteger ONE= new BigInteger("1");
	public static int length=20;
	public static long avgm=0;
	public static int count=0;
	

    /* Functions used for performing various
	   Row Column operations and evaluating subkeys of
	   the input key.
	*/
	
	
	public static int Substitute_Nibble(int c)
	{
	    if(encrypt==true)
	    {
	        int t1,t2,t3,t4;
	        t1=(0xf000 & c)>>12;
	        t2=(0x0f00 & c)>>8;
	        t3=(0x00f0 & c)>>4;
	        t4=(0x000f & c);
	        
	        return ((Sbox[t1]<<12) | (Sbox[t2]<<8) | (Sbox[t3]<<4) | (Sbox[t4]));
	    }
	    else
	    {
	        int temp1,temp2;
	        temp1=(c & 0xf0)>>4;
	        temp2=(c & 0x0f);

	        return (Sbox[temp1]<<4 | Sbox[temp2]);
	    }
	}

	
	
	/*The function Shift_Rows shifts
	  the rows nibbles by 16-bit.
	*/
	
	
	public static int Shift_Rows(int c)
	{
	    if(encrypt==true)
	    return ((c & 0x0f00)>>8 | (c & 0x000f)<<8 | (c & 0xf0f0));
	    else
	    return ((c & 0xf0)>>4 | (c & 0x0f)<<4);
	}

	
	
	
	/*This function is udes for key generation.
	  First we divide the key into two sub keys w0 and w1.
	  Secondly, we will find aint other subkeys using for loop,w0 and w1.
	*/
	
	
	public static void GenrateAllSubKeys()
	{
	    w[0]=(0xff00 & key)>>8;
	    w[1]=(0x00ff & key);
	    int i;
	    for(i=2;i<=5;i++)
	    {
	        if(i%2==0)
	        w[i]=w[i-2]^RoundConstant[i-2]^Substitute_Nibble(Shift_Rows(w[i-1]));
	        else
	        w[i]=w[i-1]^w[i-2];
	    }
	}

	/* This function is used for
	   generating all round keys. 
	*/
	
	
	
	public static void RoundKey()
	{
	    skey[0]=(w[0]<<8 | w[1]);
	    skey[1]=(w[2]<<8 | w[3]);
	    skey[2]=(w[4]<<8 | w[5]);
	}

	
	
	
	/* Adding the roundkey
	   to the cipher.
	*/
	
	
	public static int Add_Round_Key(int m,int k)
	{
	    return (m^k);
	}

	
	
	
	/*This function is for 
	polynomial multiplication.
	*/
	public static int  gmul(int  m1,int  m2)
	{
	    int res=0x0;
	    int j=0;
	    while(m1>0){
	        res=((m1&0x0001)*(m2<<j))^res;
	        m1=m1>>1;
	        j=j+1;
	    }
	    return res;
	}

	
	
	
	//bitwise polynomial modulo 19 multiplication
	public static int bitmul(int b1,int b2)
	{
	    int mul=gmul(b1,b2);
	   // printf("%x  ",mul);
	    int shift=0;
	    while(mul>15){
	        shift=(int)(Math.ceil(Math.log(mul+1)/Math.log(2)))-(int)(Math.ceil(Math.log(0x13)/Math.log(2)));
	        mul=mul^(0x13<<shift);
	        //printf("%d",mul);
	    }
	    return mul;
	}
	
	
	
	
	//mix columns [1,4 ; 4,1] encoding
	public static int Mix_Col(int c)
	{
	    int[] s = new int[4];
	    int[] st = new int[4];

	    s[0]=((0xf000 & c)>>12)&0x000f;
	    s[1]=(0x0f00 & c)>>8;
	    s[2]=(0x00f0 & c)>>4;
	    s[3]=(0x000f & c);

	    st[0]=bitmul(MixMat[0][0],s[0])^bitmul(MixMat[0][1],s[1]);
	    st[1]=bitmul(MixMat[0][1],s[0])^bitmul(MixMat[0][0],s[1]);
	    st[2]=bitmul(MixMat[1][1],s[2])^bitmul(MixMat[1][0],s[3]);
	    st[3]=bitmul(MixMat[1][0],s[2])^bitmul(MixMat[1][1],s[3]);

	    return ((st[0]<<12) | (st[1]<<8) | (st[2]<<4) | (st[3]));
	}
	
	
	
	
	// Encryption starts
	//round0
	public static void round0()
	{
	    encrypt = true;
	    ciph=Add_Round_Key(msg,skey[0]);
	    Round_0=Round_0+Integer.toHexString(ciph);
	}


	//round1
	public static void round1()
	{
	    ciph=Substitute_Nibble(ciph);
	    Round_1_S_N=Round_1_S_N+Integer.toHexString(ciph);
	    ciph=Shift_Rows(ciph);
	    Round_1_S_R=Round_1_S_R+Integer.toHexString(ciph);
	    ciph=Mix_Col(ciph);
	    Round_1_M_C=Round_1_M_C+Integer.toHexString(ciph);
	    ciph=Add_Round_Key(ciph,skey[1]);
	    Round_1_ARK=Round_1_ARK+Integer.toHexString(ciph);
	}
	//final round
	
	
	
	public static void round2()
	{
	    ciph=Substitute_Nibble(ciph);
	    Round_2_S_N=Round_2_S_N+Integer.toHexString(ciph);
	    ciph=Shift_Rows(ciph);
	    Round_2_S_R=Round_2_S_R+Integer.toHexString(ciph);
	    ciph=Add_Round_Key(ciph,skey[2]);
	    Round_2_ARK=Round_2_ARK+Integer.toHexString(ciph);

	    encrypt = false;
	}

	
	
	
	public static String StringToHexadecimal(String input)
	{
		StringBuffer sb = new StringBuffer();
	    char ch[] = input.toCharArray();
	    for(int i = 0; i < ch.length; i++)
	    {
	        String hexString = Integer.toHexString(ch[i]);
	        sb.append(hexString);
	    }
	    String result = sb.toString();
	   	return result;
	}

	
	
	
	public static String ProperString(String str,int len)
	{
		String res = String.join("", Collections.nCopies(Math.max(len-str.length(),0), "0")) + str;
		return res;
	}

	
	
	
	public static String sixteenbitbinary(int c)
	{
		String ret = Integer.toBinaryString(c);
		String res = String.join("", Collections.nCopies(16-ret.length(), "0")) + ret;
		return res;
	}




	// key Genration in RSA
	// P and Q are parameters
	// N = p*q
	// phi(N) = (p-1)*(Q-1);
	// after we have to calculate e
	// e = But e Must be
	// An integer.
	// Not be a factor of n. 
	// 1 < e < Φ(n) [Φ(n) is discussed below], 
	// Our Public Key is made of n and e
	// Generating Private Key :
	// 	We need to calculate Φ(n) :
	// Such that Φ(n) = (P-1)(Q-1)     	
	// Now calculate Private Key, d : 
	// d = (k*Φ(n) + 1) / e for some integer k
	public static void KeyGenration_RSA()
	{
		Random rand = new Random();
		N1=p.multiply(q);
		phi=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		e1=BigInteger.probablePrime(length, rand); 
		for(BigInteger i=BigInteger.ZERO;i.compareTo(N1)<0;i.add(BigInteger.ONE))
		{
			if((e1.gcd(phi).equals(BigInteger.ONE)) && (e1.compareTo(phi)<0) && ((BigInteger.ONE).compareTo(e1)<0))
			{
				break;
			}
			else
			{
				e1=BigInteger.probablePrime(length, rand);
			}
		}
		d1=e1.modInverse(phi);
	}




	//Encrypted Data = M^e mod N
	public static BigInteger encrypt(BigInteger mssg)
	{ 
		BigInteger t=mssg.modPow(e, N);	 
		return t;
	}




	// Encrypted Data  = (Encrypted Data)^d mod N 
	public static BigInteger decrypt(BigInteger mssg)
	{
		BigInteger w=mssg.modPow(d1, N1);
		return w;
	}




	//This Algorithms are initialize in static method called getInstance(). 
	//After selecting the algorithm it calculate the digest value 
	//and return the results in byte array.
	public static BigInteger getCryptoHash(String input, String algorithm) {
        try {
            //MessageDigest classes Static getInstance method is called with MD5 hashing
            MessageDigest msgDigest = MessageDigest.getInstance(algorithm);
            byte[] inputDigest = msgDigest.digest(input.getBytes());
            BigInteger inputDigestBigInt = new BigInteger(1, inputDigest);
             return inputDigestBigInt;
            //Add preceding 0's to pad the hashtext to make it 32 bit
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


	public static void main(String[] args) throws IOException{
		ServerSocket ss = new ServerSocket(4999);
		Socket s = ss.accept();
		System.out.println("Server Connected");
		Scanner in = new Scanner(System.in);
		InputStreamReader inp = new InputStreamReader(s.getInputStream());
		BufferedReader bf = new BufferedReader(inp);
		PrintWriter out = new PrintWriter(s.getOutputStream());

		
		
		
		// taking server public key (e,N);
		String serverpublickey_e = bf.readLine();
		String serverpublickey_N = bf.readLine();
		e = new BigInteger(serverpublickey_e);
		N = new BigInteger(serverpublickey_N);


        
		
		
		// taking input for public and private 
		// key parameters
		System.out.println("Enter the public and private key parameters p and Q: ");
		String Para_1  = in.nextLine();
		p = new BigInteger(Para_1);
		String Para_2 = in.nextLine();
		q = new BigInteger(Para_2);

		
		// key Genration using P and Q
		KeyGenration_RSA();
 

		// plain text and secret key
		System.out.println("Enter the plain text: ");
		String message = in.nextLine();
		System.out.println("Enter the 16-bit key: ");
		String secretkey = in.nextLine();
		String z = secretkey;
		int zz = Integer.parseInt(z,2); // chaning into binary aaray



		// Encrytpion of secret key using RSA
		// and public key of server
		BigInteger inn = BigInteger.valueOf(zz);
		BigInteger encryptedsecretkey=encrypt(inn);

        

		// AES
		key = Integer.parseInt(secretkey,2);
		int len = message.length();
		String ret="";
		for(int i=0;i+1<len;i+=2)
		{
			msg = Integer.parseInt(StringToHexadecimal(message.substring(i,i+2)),16);
			GenrateAllSubKeys();
			RoundKey();

			round0();
			round1();
			round2();

			String res = Integer.toHexString(ciph);
			ret=ret.concat(ProperString(res,4));
		}
		if(len%2==1)
		{
			msg = Integer.parseInt(StringToHexadecimal(message.substring(len-1,len)),16);
			GenrateAllSubKeys();
			RoundKey();
			round0();
			round1();
			round2();

			String res = Integer.toHexString(ciph);
			ret=ret.concat(ProperString(res,2));
		}
		String ciphertext = ret;

		
		
		
		// Hashing 
		System.out.println("Enter the Algo for creating the message digest MD5, SHA-1, SHA-256, SHA-512,");
		String algorithm  = in.nextLine();
		BigInteger messagedigest = getCryptoHash(message,algorithm);
		BigInteger temp4 = messagedigest.modPow(ONE, N1);	 




		// Client Signature using Client private key
		// private key (d,N);
		BigInteger clientsignature = decrypt(temp4);


        // client side output
		System.out.println("Plain Text:                                "+message);
		System.out.println("Secrete Key:                                "+z);
		System.out.println("public and private key parameters P and Q:  "+p+" "+q);
		System.out.println("client pblic key(e,N):                      "+ e1+" "+N1);
		System.out.println("The EncryptedSecretKey is:                  "+ encryptedsecretkey);
		System.out.println("The CipherText is:                          "+ ciphertext);
		System.out.println("messagedigest:                              "+ temp4);
		System.out.println("The ClientSignature is:                     "+clientsignature);


		// maessage flow to server side
		String temp = clientsignature.toString(10);// client signature
		out.println(""+temp);
		out.println(""+ciphertext);  // cipher text
		String temp2 = encryptedsecretkey.toString(10); // encrypted sercret key
		out.println(""+temp2);
		String temp3 = e1.toString(10); // client public key e
		out.println(""+ temp3); 
		String temp5 = N1.toString(10); // client public key N
		out.println(""+ temp5);
		out.println(""+ algorithm);    // hashing algo
		out.flush();
	}
}
