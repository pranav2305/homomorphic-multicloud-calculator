import * as paillier from "paillier-bigint";
import * as bigInt from "big-integer";

export const add = async () => {
  // generate Paillier keypair
  const { publicKey, privateKey } = await paillier.generateRandomKeys(3072);

  // encrypt two numbers
  const num1 = 10;
  const num2 = 5;
  const encNum1 = publicKey.encrypt(num1);
  const encNum2 = publicKey.encrypt(num2);

  // add the encrypted numbers
  const encSum = publicKey.addition(encNum1, encNum2);

  // decrypt the result
  const sum = privateKey.decrypt(encSum);

  console.log(`The sum of ${num1} and ${num2} is ${sum}`);
};

export const multiply = async () => {
  // Generate a new key pair
  const { publicKey, privateKey } = await paillier.generateRandomKeys(1024);

  // Encrypt two numbers
  const num1 = 5;
  const num2 = 7;
  const encryptedNum1 = bigInt(publicKey.encrypt(num1));
  const encryptedNum2 = bigInt(publicKey.encrypt(num2));

  // Homomorphically multiply the encrypted numbers
  const encryptedResult = publicKey.addition(
    bigInt(encryptedNum1).multiply(
      bigInt(encryptedNum2).modPow(publicKey.g, publicKey._n2)
    ).value,
    1n
  );

  // Decrypt the result
  const decryptedResult = privateKey.decrypt(encryptedResult);
  console.log(decryptedResult); // Output: 35
};

class PublicKey {
  constructor(G, P, Y) {
    this.G = G;
    this.P = P;
    this.Y = Y;
  }
}

class PrivateKey extends PublicKey {
  constructor(G, P, Y, X) {
    super(G, P, Y);
    this.X = X;
  }
}

function encrypt(pubKey, message) {
  const k = bigInt.randBetween(1, pubKey.P.minus(1));
  const m = bigInt(message);

  const a = pubKey.G.modPow(k, pubKey.P);
  const s = pubKey.Y.modPow(k, pubKey.P);
  const gm = pubKey.G.modPow(m, pubKey.P);

  let b = s.multiply(gm);
  b = b.mod(pubKey.P);

  return [a, b];
}

function decrypt(privKey, a, b) {
  let s = a.modPow(privKey.X, privKey.P);
  s = s.modInv(privKey.P);
  s = s.multiply(b);
  s = s.mod(privKey.P);

  return s;
}

function getGP(plen) {
  let p = bigInt.zero;
  while (p.bitLength() !== parseInt(plen)) {
    const buf = "FCA682CE8E12CABA26EFCCF7110E526DB078B05EDECBCD1EB4A208F3AE1617AE01F35B91A47E6DF63413C5E12ED0899BCD132ACD50D99151BDC43EE737592E17";
    p = bigInt(buf, 16);
    p = p.or(bigInt.one.shiftLeft(parseInt(plen) - 1));
  }
  const G = bigInt(2);
  const Y = G.modPow(bigInt.zero, p);

  return [G, p, Y];
}

export function test() {
  const plen = "512";
  const val1 = "4";
  const val2 = "4";
  let x = "40";

  // const args = process.argv.slice(2);
  // if (args.length > 0) val1 = args[0];
  // if (args.length > 1) val2 = args[1];
  // if (args.length > 2) x = args[2];
  // if (args.length > 3) plen = args[3];

  console.log(`Prime number size: ${plen}\n`);

  const [G, P, Y] = getGP(plen);
  const xval = bigInt(x);

  const privKey = new PrivateKey(G, P, Y, xval);
  privKey.Y = G.modPow(privKey.X, privKey.P);

  const [a1, b1] = encrypt(privKey, val1);
  const [a2, b2] = encrypt(privKey, val2);

  const message2 = decrypt(privKey, a1.multiply(a2), b1.multiply(b2));

  console.log(`====Values (val1=${val1} and val2=${val2})`);
  console.log(`====Private key (x):\nX=${privKey.X.toString()}`);
  console.log(
    `====Public key (Y=${privKey.Y.toString()}, G=${G.toString()}, P=${P.toString()})\n`
  );
  console.log(`====Cipher (a1=${a1.toString()})\n(b1=${b1.toString()}): `);
  console.log(`\n====Decrypted: ${message2.toString()}`);

  for (let i = 1; i <= 1000000; i++) {
    const m = bigInt(i);
    const gm = G.modPow(m, P);
    if (gm.compare(message2) === 0) {
      console.log(`\n====Decrypted: ${i}`);
      break;
    }
  }
}
