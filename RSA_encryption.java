import java.math.BigInteger;
import java.nio.file.attribute.AclEntry.Builder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Stack;

public class RSA_encryption {
	public static char[] coder = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
			'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', ' ' };
	public static Map<Character, Integer> map = new HashMap<Character, Integer>();

	public static void doMapping() {
		int i = 0;
		for (char c : coder) {
			map.put(c, i + 2);
			i++;
		}
	}

	public static void main(String[] args) {

		doMapping();

		/* declared variable for mentioned prime number set */
		int pa = 97;
		int qa = 113;
		int pb = 127;
		int qb = 73;

		System.out.println("Answer for 2.A ");
		/*
		 * computing n for alice by multiplying pa and qa and n for bob by multiplying
		 * pb and qb
		 ****/
		int na = pa * qa;
		int nb = pb * qb;
		System.out.println("na : " + na + "\nnb : " + nb);
		/* computing phi for alice and bob by multiplying ****/
		int phi_a = (pa - 1) * (qa - 1);
		int phi_b = (pb - 1) * (qb - 1);
		System.out.println("phi_a : " + phi_a + "\nphi_b : " + phi_b);

//alice choose 73 as public key and bob choose 41 as public key
		int public_a = 73;
		int public_b = 41;

// finding corresponding private key for alice and bob
		int private_a = findInverse(phi_a, public_a);
		System.out.print("\nInverse of la is: " + private_a);

		int private_b = findInverse(phi_b, public_b);
		System.out.print("\nInverse of lb is : " + private_b);

		if (public_a > private_a) {
			int temp = private_a;
			private_a = public_a;
			public_a = temp;
		}
		if (public_b > private_b) {
			int temp = private_b;
			private_b = public_b;
			public_b = temp;
		}
		System.out.print("\n2. B ");
		System.out
				.print("\npublic key for alice is  is : " + public_a + "\nprivate key for alice is  is : " + private_a);
		System.out.print("\npublic key for bob is : " + public_b + "\nprivate key for bob is  is : " + private_b);

		/*
		 * bob wants to send the message "buy google" to alice so it will encode with
		 * it's private key
		 */
		System.out.print("\n2. C ");
		String message = "buy google";
		String encoded_message = computeEncryptedMessage(message, private_b, nb);
		System.out.print("\nencoded message after applying bob's private key : " + encoded_message);

		/* bob wants to add his signature to the same code String */
		System.out.print("\n2. D ");
		String bob_sign = "bob";
		String encoded_sign = computeEncryptedMessage(bob_sign, public_a, na);
		System.out.print("\nencoded_message of bob's sign : " + encoded_sign);
		String final_encoded_message = encoded_sign + encoded_message;

		System.out.print("\nfinal_encoded_message : " + final_encoded_message);

		/*
		 * Alice has to decode first 15 charecter of encoded message using own private
		 * key to ascertain it is from bob
		 */
		String enocded_sign_from_bob = final_encoded_message.substring(0, 15);

		String decoded_sign = computeDecryptedMessage(enocded_sign_from_bob, private_a, na);
		if (decoded_sign.equals(bob_sign)) {
			System.out.print("\nYes!! Message is from bob." + " bob's sign :" + decoded_sign);
		}
		/*
		 * Alice has to decode  15 charecter onwards message using its bob's public
		 * key to find out the message
		 */
		String enocded_message_from_bob = final_encoded_message.substring(15);
		String decoded_message = computeDecryptedMessage(enocded_message_from_bob, public_b, nb);
		System.out.print("\nMessage from bob is : " + decoded_message);
	}

	public static int findInverse(int m, int n) {
		if (n == 0) {
			return 0;
		}
		if (n == 1) {
			return 1;
		}
		Stack<Integer> stack = new Stack<Integer>();
		int d = 1;
		int a = m;
		int b = n;
		int r = Integer.MIN_VALUE;
		while (true) {
			r = a % b;
			stack.push(a / b);
			if (r == 0) {
				d = b;
				break;
			}
			int temp = b;
			b = r;
			a = temp;
		}
		int x = 1;
		int y = 0;
		int s = stack.size();
		int i = s;
		while (i > 0) {
			int temp = y;
			int z = stack.pop();
			y = x - (y * z);
			x = temp;
			i--;
		}
		if (y < 0) {
			y = m + y;
		}
		return y;
	}

	public static String computeEncryptedMessage(String str, int key, int n_value) {

		int len = String.valueOf(n_value).length();
		StringBuilder builder = new StringBuilder();
		BigInteger key_b = BigInteger.valueOf(key);
		BigInteger n_value_b = BigInteger.valueOf(n_value);
		char[] input = str.toCharArray();
		for (char c : input) {
			int code = map.get(c);
			BigInteger code_b = BigInteger.valueOf(code);
			BigInteger encoded_code = code_b.modPow(key_b, n_value_b);
			int len_e = String.valueOf(encoded_code).length();
			if( len_e != len)
			{
				for(int i =0; i < len-len_e; i++)
				{
					builder.append(0);
				}
			}
			builder.append(encoded_code);
		}

		return builder.toString();
	}

	public static String computeDecryptedMessage(String str, int key, int n_value) {

		StringBuilder builder = new StringBuilder();
		StringBuilder sign = new StringBuilder();
		BigInteger key_b = BigInteger.valueOf(key);
		BigInteger n_value_b = BigInteger.valueOf(n_value);
		int n = String.valueOf(n_value).length();
		
		char[] input = str.toCharArray();
		int i = 0;
	
		while (i < input.length) {
			for (int j = 0; j < n; j++) {
				builder.append(input[i + j]);
			}

			BigInteger number = BigInteger.valueOf(Integer.parseInt(builder.toString()));
			BigInteger e = number.modPow(key_b, n_value_b);
			sign.append(coder[e.intValue() - 2]);
			builder.delete(0, n);
			i = i+n;
		}
		return sign.toString();
	}
}
