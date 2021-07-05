import java.net.*;
import java.io.*;
import java.lang.Math;
import java.util.*;
import java.math.BigInteger;
import java.math.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;





public class server{
	/* Below are some global variables used in the code.
	   Their functioning can be easily understood by their name.
	*/
	public static boolean decrypt = false;
	public static int[] Sbox = new int[]{0x09,0x04,0x0a,0x0b,0x0d,0x01,0x08,0x05,0x06,0x02,0x00,0x03,0x0c,0x0e,0x0f,0x07};
	public static int[] SIbox = new int[]{0x0a,0x05,0x09,0x0b,0x01,0x07,0x08,0x0f,0x06,0x00,0x02,0x03,0x0c,0x04,0x0d,0x0e};
	public static int[] RoundConstant = new int[]{0x80,0xaa,0x30};
	public static int[][] InMixMat = {{9,2},{2,9}};
	public static int key;
	public static int ciph,dmsg;
	public static int[] skey = new int[]{0,0,0};
	public static int[] w = new int[]{0,0,0,0,0,0};
	public static int[] intArray = new int[]{1,2,3,4,5,6,7,8,9,10};
	public static String preround="",round1sn="",round1sr="",round1mix="",round1ark="",round2sn="",round2sr="",round2ark="";
	public static BigInteger p,q,N,N1,e,e1,d,d1,phi;
	public static BigInteger ONE= new BigInteger("1");
	public static int length=20;
	public static long avgm=0;
	public static int count=0;





	public static int Substitute_Nibble(int c)
	{
	    if(decrypt==true)
	    {
	        int t1,t2,t3,t4;
	        t1=(0xf000 & c)>>12;
	        t2=(0x0f00 & c)>>8;
	        t3=(0x00f0 & c)>>4;
	        t4=(0x000f & c);
	        
	        return ((SIbox[t1]<<12) | (SIbox[t2]<<8) | (SIbox[t3]<<4) | (SIbox[t4]));
	    }
	    else
	    {
	        int temp1,temp2;
	        temp1=(c & 0xf0)>>4;
	        temp2=(c & 0x0f);

	        return (Sbox[temp1]<<4 | Sbox[temp2]);
	    }
	}


	//shift rows nibbles 16-bit
	public static int Shift_Rows(int c)
	{
	    if(decrypt==true)
	    return ((c & 0x0f00)>>8 | (c & 0x000f)<<8 | (c & 0xf0f0));
	    else
	    return ((c & 0xf0)>>4 | (c & 0x0f)<<4);
	}


	//key generation
	//1st :- divide the key into two sub key w0,w1
	//2nd :- Find aint other subkeys using for loop,w0,w1
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


	//generating roundkeys
	public static void RoundKey()
	{
	    skey[0]=(w[0]<<8 | w[1]);
	    skey[1]=(w[2]<<8 | w[3]);
	    skey[2]=(w[4]<<8 | w[5]);
	}


	//add round key
	public static int ark(int m,int k)
	{
	    return (m^k);
	}


	//polynomial multiplication
	public static int  gmul(int  m1,int  m2)
	{
	    int res=0x0;
	    int j=0;
	    while(m1>0)
		{
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
	    int shift=0;
	    while(mul>15)
		{
	        shift=(int)(Math.ceil(Math.log(mul+1)/Math.log(2)))-(int)(Math.ceil(Math.log(0x13)/Math.log(2)));
	        mul=mul^(0x13<<shift);
	    }
	    return mul;
	}


	//mix columns [1,4 ; 4,1] encoding
	public static int mixcol(int c)
	{
	    int[] s = new int[4];
	    int[] st = new int[4];
	    s[0]=((0xf000 & c)>>12)&0x000f;
        s[1]=(0x0f00 & c)>>8;
        s[2]=(0x00f0 & c)>>4;
        s[3]=(0x000f & c);
        
        st[0]=bitmul(InMixMat[0][0],s[0])^bitmul(InMixMat[0][1],s[1]);
        st[1]=bitmul(InMixMat[0][1],s[0])^bitmul(InMixMat[0][0],s[1]);
        st[2]=bitmul(InMixMat[1][1],s[2])^bitmul(InMixMat[1][0],s[3]);
        st[3]=bitmul(InMixMat[1][0],s[2])^bitmul(InMixMat[1][1],s[3]);
        
        return ((st[0]<<12) | (st[1]<<8) | (st[2]<<4) | (st[3]));
	}


	// Decryption starts
	//round2
	public static void dround0()
	{
	    decrypt = true;
	    dmsg=ark(ciph,skey[2]);
	    preround=preround+Integer.toHexString(dmsg);
	}


	public static void dround1()
	{
	    dmsg=Substitute_Nibble(dmsg);
	    round1sn=round1sn+Integer.toHexString(dmsg);
	   	dmsg=Shift_Rows(dmsg);
	    round1sr=round1sr+Integer.toHexString(dmsg);
	    dmsg=ark(dmsg,skey[1]);
	    round1ark=round1ark+Integer.toHexString(dmsg);
	    dmsg=mixcol(dmsg);
	    round1mix=round1mix+Integer.toHexString(dmsg);
	}


	public static void dround2()
	{
	    dmsg=Substitute_Nibble(dmsg);
	    round2sn=round2sn+Integer.toHexString(dmsg);
	    dmsg=Shift_Rows(dmsg);
	    round2sr=round2sr+Integer.toHexString(dmsg);
	    dmsg=ark(dmsg,skey[0]);
	    round2ark=round2ark+Integer.toHexString(dmsg);
	    decrypt = false;
	}




	public static String HexadecimalToString(String str)
	{
		String result = new String();
      	char[] charArray = str.toCharArray();
      	for(int i = 0; i < charArray.length; i=i+2)
      	{
         	String st = ""+charArray[i]+""+charArray[i+1];
         	char ch = (char)Integer.parseInt(st, 16);
        	result = result + ch;
      	}
      	return result;
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
	public static BigInteger encryptt(BigInteger mssg)
	{ 
		BigInteger t=mssg.modPow(e, N);	 
		return t;
	}




	// Decrypted Data  = (Encrypted Data)^d mod N 
	public static BigInteger decryptt(BigInteger mssg)
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
		Socket s = new Socket("localhost",4999);
		Scanner in = new Scanner(System.in);
		PrintWriter out = new PrintWriter(s.getOutputStream());
		InputStreamReader inp = new InputStreamReader(s.getInputStream());
		BufferedReader bf = new BufferedReader(inp);



		// taking input for public and private 
		// key parameters
		System.out.println("Enter the public and private key parameters P and Q: ");
		String Para_1  = in.nextLine();
		p = new BigInteger(Para_1);
		String Para_2 = in.nextLine();
		q = new BigInteger(Para_2);


		// key Genration using P and Q
		KeyGenration_RSA();


		System.out.println("e1: "+e1);
		

		String t3 = e1.toString(10); 
		String t4 = N1.toString(10);
		out.println(""+t3);
		out.println(""+t4);
		out.flush();


		
		
		// taking input from client side
		String clientsignature = bf.readLine();
		String ciphertext = bf.readLine();
		String encryptedsecretkey = bf.readLine();
		String clientpublickey_e = bf.readLine();
		String clientpublickey_N = bf.readLine();
		String algorithm = bf.readLine();
		BigInteger cs = new BigInteger(clientsignature); //cs => clientsignature
		BigInteger  esk = new BigInteger(encryptedsecretkey); // esk  => encryptedsecretkey
		e = new BigInteger(clientpublickey_e);
		N = new BigInteger(clientpublickey_N);




		BigInteger temp = decryptt(esk);
		String secretkey = temp.toString(2);
		



		String binnum1 = ciphertext;
		String binnum2 = secretkey;
		key = Integer.parseInt(binnum2,2);




		String ret="";
		int len = binnum1.length();
		GenrateAllSubKeys();
		RoundKey();
		for(int i=0;i+3<len;i+=4)
		{
			ciph = Integer.parseInt(binnum1.substring(i,i+4),16);

			dround0();
	    	dround1();
	    	dround2();

	    	String res = Integer.toHexString(dmsg);
	    	ret = ret.concat(HexadecimalToString(res));
		}
		if(len%4!=0)
		{
			ciph = Integer.parseInt(binnum1.substring(len-2,len),16);

			dround0();
	    	dround1();
	    	dround2();

	    	String res = Integer.toHexString(dmsg);
	    	ret = ret.concat(HexadecimalToString(res));
		}




		BigInteger messagedigest = getCryptoHash(ret,algorithm);
		BigInteger temp5 = messagedigest.modPow(ONE, N);
		BigInteger signature = encryptt(cs);

		boolean response = temp5.equals(signature);



		System.out.println("public and private key parameters P and Q:  "+p+" "+q);
		System.out.println("server pblic key(e,N):                      "+ e1+" "+N1);
		System.out.println("The Decrypted Secret key: is:               "+ secretkey);
		System.out.println("The Decoded cipher text:                    "+ ret);
		System.out.println("messagedigest:                              "+ temp5);
		System.out.println("The Intermediated Verification code:        "+signature);
		System.out.println(" ");
		System.out.println(" ");
		System.out.println(" ");

		if (response) 
		{
  			System.out.println("                     Signature verified  :)                   ");
        }
        else {
  
            System.out.println("                    Signature Not Verified  ^_^               ");
        }


	}
}
