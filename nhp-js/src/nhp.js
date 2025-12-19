export {bytesToBase64, base64ToBytes, bytesToString, stringToBytes, getUnixNano} from "./utils.js"
export {generateX25519KeyPair, generateX25519KeyPairBase64} from "./crypto.js"
import {ecdhX25519, bytesToX25519PublicKey, x25519PublicKeyToBytes, bytesToX25519PrivateKey, x25519PrivateKeyToBytes, base64To25519PublicKey, base64To25519PrivateKey, mixKey, generateX25519KeyPair} from "./crypto.js"
import {chacha20Seal, chacha20Open} from "./crypto.js"
import {newSHA256Hash, updateSHA256, sumSHA256, keyGen1, keyGen2} from "./crypto.js"
import { getUnixNano } from "./utils.js"

const PacketBufferSize = 4096;
const InitialChainKeyString = "NHP keygen v.20230421@clouddeep.cn"
const	InitialHashString     = "NHP hashgen v.20230421@deepcloudsdp.com"
const GlobalCounter = new BigUint64Array(1);

class NHPHeader {
  static SIZE = 240;

  constructor(buffer, offset = 0) {
    this.view = new DataView(buffer, offset, Header.SIZE);
    this.bytes = new Uint8Array(buffer, offset);
  }

  get typeAndPayloadSize() {
    const val = (this.view.getUint32(0) ^ this.view.getUint32(4)) >>> 0;
    return {
      type: ((val & 0xFFFF0000) >>> 16) >>> 0,
      size: (val & 0x0000FFFF) >>> 0
    }
  }

  set typeAndPayloadSize({type, size}) {
    const preamble = new Uint32Array(1)
    window.crypto.subtle.getRandomValues(preamble)
    let tns = (type & 0x0000FFFF << 16 | size & 0x0000FFFF) >>> 0;
    tns = (preamble[0] ^ tns) >>> 0;
    this.view.setUint32(0, preamble[0]);
    this.view.setUint32(4, tns); 
  }

  get version() { return {major: this.view.getUint8(8), minor: this.view.getUint8(9)}; }
  set version({major, minor}) { this.view.setUint8(8, major); this.view.setUint8(9, minor); }

  get flags() {
    const flag = this.view.getUint16(10);
    return {
      extended: Boolean((flag & 0x1) >>> 0),
      compressed: Boolean((flag & 0x2) >>> 0)
    }
  }
  set flags({extended, compressed}) {
    const flag = Uint16Array(1)
    if (extended) {
      flag[0] = (flag[0] | 0x1) >>> 0;
    }
    if (compressed) {
      flag[0] = (flag[0] | 0x2) >>> 0;
    }
    this.view.setUint16(10, flag[0]);
  }

  get counter() { return this.view.getBigUint64(16); }
  set counter(v) { this.view.setBigUint64(v); }

  get nonce() {
    const bytes = new Uint8Array(12);
    bytes.set(this.bytes.subarray(16, 24), 4);
    return bytes;
  }

  get ephermeral() { return this.bytes.subarray(24, 24+32); }
  set ephermeral(bytes) {
    if (bytes.length == 32) {
      this.bytes.set(bytes, 24);
    }
  }

  get identity() { return this.bytes.subarray(56, 56+80); }
  set identity(bytes) {
    if (bytes.length == 80) {
      this.bytes.set(bytes, 56);
    }
  }

  get static() { return this.bytes.subarray(136, 136+48); }
  set static(bytes) {
    if (bytes.length == 48) {
      this.bytes.set(bytes, 136);
    }
  }

  get timestamp() { return this.bytes.subarray(184, 184+24); }
  set timestamp(bytes) {
    if (bytes.length == 24) {
      this.bytes.set(bytes, 184);
    }
  }

  get hmac() { return this.bytes.subarray(208, 208+32); }
  set hmac(bytes) {
    if (bytes.length == 32) {
      this.bytes.set(bytes, 208);
    }
  }
}

export async function buildNHPPacket(type, privateKey, publicKey, remotePublicKey, msg) {
  const packet = new Uint8Array(PacketBufferSize);
  const header = new NHPHeader(packet.buffer);

  const localPrivKey = await base64To25519PrivateKey(privateKey)
  const localPubKey = await base64To25519PublicKey(publicKey)
  const remotePubKey = await base64To25519PublicKey(remotePublicKey)

  const payloadSize = msg.length + 16;
  header.typeAndPayloadSize = {type, payloadSize};
  header.version = {major: 1, minor: 0};
  GlobalCounter[0]++;
  header.counter = GlobalCounter[0];
  const nonce = header.nonce;

  const chainKey = new Uint8Array(32);
  const chainHash = new Uint8Array(32);
  const hmacHasher = newSHA256Hash();
  const chainHasher = newSHA256Hash();

  updateSHA256(hmacHasher, stringToBytes(InitialHashString));
  updateSHA256(chainHasher, stringToBytes(InitialHashString));
  chainHash.set(sumSHA256(chainHasher));
  chainKey.set(mixKey(chainHash, stringToBytes(InitialChainKeyString)));

  updateSHA256(hmacHasher, remotePublicKey);
  updateSHA256(chainHasher, remotePublicKey);

  const ephermeralKeys = await generateX25519KeyPair();
  const ePublickey = await x25519PublicKeyToBytes(ephermeralKeys.publicKey);
  header.ephermeral = ePublickey;
  updateSHA256(chainHasher, ePublickey);
  chainHash.set(sumSHA256(chainHasher));
  chainKey.set(mixKey(chainKey, ePublickey));

  const essKey = await ecdhX25519(ephermeralKeys.privateKey, remotePubKey);
  const ess = await x25519PublicKeyToBytes(essKey);

  // encrypt local public key
  const derivedKeys0 = keyGen2(chainKey, ess);
  chainKey.set(derivedKeys0.first);
  const keyStatic = await chacha20Seal(derivedKeys0.second, nonce, publicKey, chainHash);
  header.static = keyStatic

  updateSHA256(chainHasher, keyStatic);
  chainHash.set(sumSHA256(chainHasher));

  const ssKey = await ecdhX25519(localPrivKey, remotePubKey);
  const ss = await x25519PublicKeyToBytes(ssKey);

  // encrypt timestamp
  const derivedKeys1 = keyGen2(chainKey, ss);
  chainKey.set(derivedKeys1.first);

  const tsBuf = new ArrayBuffer(8)
  const tsView = new DataView(tsBuf);
  tsView.setBigUint64(0, getUnixNano());
  const ts = new Uint8Array(buffer);

  const tsStatic = await chacha20Seal(derivedKeys1.second, nonce, ts, chainHash);
  header.timestamp = tsStatic

  // encrypt msg
  const derivedKeys2 = keyGen2(chainKey, tsStatic);
  chainKey.set(derivedKeys2.first);
  updateSHA256(chainHasher, tsStatic);
  chainHash.set(sumSHA256(chainHasher));

  const msgStatic = await chacha20Seal(derivedKeys2.second, nonce, msg, chainHash);
  packet.set(msgStatic, 240)

  return packet.subarray(0, 240+msg.length+16)
}

export async function parseNHPPacket(bytes) {

}
