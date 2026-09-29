/* VaultText v2: no third-party crypto code. Web Crypto API only. */
const VaultCrypto=(()=> {
  const DB="VaultTextDB", STORE="keys", KEY_ID="totp-hmac-v1", VERSION=2;
  const ITER=600000, enc=new TextEncoder(), dec=new TextDecoder();
  const te=enc.encode.bind(enc), td=dec.decode.bind(dec);

  function b64(b){let s="",n=0x8000;for(let i=0;i<b.length;i+=n)s+=String.fromCharCode(...b.subarray(i,i+n));return btoa(s)}
  function ub64(s){const x=atob(s),o=new Uint8Array(x.length);for(let i=0;i<x.length;i++)o[i]=x.charCodeAt(i);return o}
  function hex(b){return [...b].map(x=>x.toString(16).padStart(2,"0")).join("")}
  function normTotp(v){v=String(v).replace(/\D/g,"");if(!/^\d{6}$/.test(v))throw Error("Введите ровно 6 цифр.");return v}
  function openDB(){return new Promise((res,rej)=>{const r=indexedDB.open(DB,1);r.onupgradeneeded=()=>r.result.createObjectStore(STORE);r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)})}
  async function dbGet(){const db=await openDB();return new Promise((res,rej)=>{const r=db.transaction(STORE,"readonly").objectStore(STORE).get(KEY_ID);r.onsuccess=()=>res(r.result||null);r.onerror=()=>rej(r.error)})}
  async function dbPut(key){const db=await openDB();return new Promise((res,rej)=>{const r=db.transaction(STORE,"readwrite").objectStore(STORE).put(key,KEY_ID);r.onsuccess=()=>res();r.onerror=()=>rej(r.error)})}
  async function dbDelete(){const db=await openDB();return new Promise((res,rej)=>{const r=db.transaction(STORE,"readwrite").objectStore(STORE).delete(KEY_ID);r.onsuccess=()=>res();r.onerror=()=>rej(r.error)})}

  function base32Encode(bytes){
    const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";let out="",bits=0,val=0;
    for(const b of bytes){val=(val<<8)|b;bits+=8;while(bits>=5){bits-=5;out+=alphabet[(val>>>bits)&31]}}
    if(bits)out+=alphabet[(val<<(5-bits))&31];return out;
  }
  function base32Decode(s){
    s=s.toUpperCase().replace(/[\s-]/g,"");const map={};"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".split("").forEach((c,i)=>map[c]=i);
    let bits=0,val=0,out=[];for(const c of s){if(!(c in map))throw Error("Неверный Base32-ключ.");val=(val<<5)|map[c];bits+=5;if(bits>=8){bits-=8;out.push((val>>>bits)&255)}}
    return new Uint8Array(out);
  }

  async function createEnrollment(){
    const raw=crypto.getRandomValues(new Uint8Array(20)); // 160-bit TOTP secret
    const key=await crypto.subtle.importKey("raw",raw,{name:"HMAC",hash:"SHA-1"},false,["sign"]);
    await dbPut(key);
    return base32Encode(raw);
  }
  async function hasSecret(){return !!(await dbGet())}
  async function getKey(){const k=await dbGet();if(!k)throw Error("Сначала настройте Google Authenticator.");return k}

  async function hmac(key,data){return new Uint8Array(await crypto.subtle.sign("HMAC",key,data))}
  async function hotp(key,counter){
    const buf=new ArrayBuffer(8),v=new DataView(buf);v.setUint32(0,Math.floor(counter/0x100000000));v.setUint32(4,counter>>>0);
    const mac=await hmac(key,new Uint8Array(buf)),off=mac[mac.length-1]&15;
    const num=((mac[off]&127)<<24)|(mac[off+1]<<16)|(mac[off+2]<<8)|mac[off+3];
    return String(num%1000000).padStart(6,"0");
  }
  async function totpAt(key,ms=Date.now()){
    return hotp(key,Math.floor(ms/30000));
  }
  async function verifyTotp(code){
    code=normTotp(code);const key=await getKey();
    const now=Date.now();
    // Accept current interval and ±1 interval for small device clock drift.
    for(const delta of [-30000,0,30000])if(code===await totpAt(key,now+delta))return true;
    return false;
  }

  async function deriveMessageKey(totpKey,salt){
    // The permanent TOTP secret is the root secret. HKDF produces a distinct
    // AES key for each message salt; TOTP itself is only the live access check.
    const rawHmac=await hmac(totpKey, new Uint8Array([...te("VaultText/root/v2"),...salt]));
    const hk=await crypto.subtle.importKey("raw",rawHmac,"HKDF",false,["deriveKey"]);
    return crypto.subtle.deriveKey(
      {name:"HKDF",hash:"SHA-256",salt,info:te("VaultText/message/v2")},
      hk,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]
    );
  }

  async function encryptText(plaintext,totp){
    normTotp(totp);if(!(await verifyTotp(totp)))throw Error("Неверный или просроченный код Google Authenticator.");
    if(!plaintext)throw Error("Введите текст.");
    const salt=crypto.getRandomValues(new Uint8Array(32)),iv=crypto.getRandomValues(new Uint8Array(12));
    const key=await deriveMessageKey(await getKey(),salt);
    const header={v:VERSION,alg:"AES-256-GCM",kdf:"HKDF-SHA-256",salt:b64(salt),iv:b64(iv)};
    const aad=te(JSON.stringify(header));
    const ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:aad},key,te(plaintext)));
    return "VT2."+b64(te(JSON.stringify(header)))+"."+b64(ct);
  }

  async function decryptText(container,totp){
    normTotp(totp);if(!(await verifyTotp(totp)))throw Error("Неверный или просроченный код Google Authenticator.");
    const p=container.trim().split(".");if(p.length!==3||p[0]!=="VT2")throw Error("Неверный формат шифр-кода.");
    let header,ct;try{header=JSON.parse(td(ub64(p[1])));ct=ub64(p[2])}catch{throw Error("Повреждённый шифр-код.")}
    if(header.v!==VERSION||header.alg!=="AES-256-GCM"||header.kdf!=="HKDF-SHA-256")throw Error("Неподдерживаемая версия.");
    const salt=ub64(header.salt),iv=ub64(header.iv);if(salt.length!==32||iv.length!==12)throw Error("Повреждённые параметры.");
    const key=await deriveMessageKey(await getKey(),salt);
    try{return td(await crypto.subtle.decrypt({name:"AES-GCM",iv,additionalData:te(JSON.stringify(header))},key,ct))}
    catch{throw Error("Не удалось расшифровать: другой экземпляр TOTP или изменённый шифр-код.")}
  }

  async function revealSecretForSetup(){ 
    // Only used immediately after generation. The raw key is otherwise never exportable.
    const k=await getKey();
    // Non-extractable keys cannot be exported; setup code is returned separately
    // from createEnrollment and should be saved by the user if recovery is needed.
    return k;
  }

  return {createEnrollment,hasSecret,verifyTotp,encryptText,decryptText,dbDelete,normTotp};
})();