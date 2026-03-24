/* =========================================
   BASIC UTILITIES
========================================= */

function textToBytes(text) {
    let arr = [];
    for (let i = 0; i < text.length; i++) {
        arr.push(text.charCodeAt(i));
    }
    return arr;
}

function bytesToText(arr) {
    let text = "";
    for (let n of arr) {
        text += String.fromCharCode(n);
    }
    return text;
}

function xor(a, b) {
    return a ^ b;
}

/* =========================================
   KEY & IV
========================================= */

function keyToNumber(keyStr){
    let sum = 0;
    for(let i=0;i<keyStr.length;i++){
        sum += keyStr.charCodeAt(i);
    }
    return sum % 256;
}

function generateIV(){
    return Math.floor(Math.random()*256);
}

/* =========================================
   AES 
========================================= */

// SBOX
const sbox = [];
for(let i=0;i<256;i++){
    sbox.push((i * 11 + 7) % 256);
}

// inverse sbox
const invSbox = [];
for(let i=0;i<256;i++){
    invSbox[sbox[i]] = i;
}

// shift 
function shift(x){
    return ((x << 1) | (x >> 7)) & 255;
}

// inverse shift
function invShift(x){
    return ((x >> 1) | (x << 7)) & 255;
}

// mix
function mix(x){
    return (x * 3) % 256;
}

// inverse mix
function invMix(x){
    return (x * 171) % 256; // inverse 3 mod 256
}

// ENCRYPT
function aesEncrypt(x, key) {

    let state = x;

    // ROUND 1
    state = sbox[state];
    state = shift(state);
    state = mix(state);
    state = state ^ key;

    // ROUND 2
    state = sbox[state];
    state = shift(state);
    state = state ^ key;

    return state;
}

// DECRYPT 
function aesDecrypt(x, key) {

    let state = x;

    // reverse ROUND 2
    state = state ^ key;
    state = invShift(state);
    state = invSbox[state];

    // reverse ROUND 1
    state = state ^ key;
    state = invMix(state);
    state = invShift(state);
    state = invSbox[state];

    return state;
}

/* =========================================
   ECB MODE
========================================= */

function encryptECB(blocks, key) {
    return blocks.map(b => aesEncrypt(b, key));
}

function decryptECB(blocks, key) {
    return blocks.map(b => aesDecrypt(b, key));
}

/* =========================================
   CBC MODE
========================================= */

function encryptCBC(blocks, key) {

    let iv = generateIV();
    let result = [iv];

    for (let b of blocks) {
        let x = xor(b, iv);
        let c = aesEncrypt(x, key);
        result.push(c);
        iv = c;
    }

    return result;
}

function decryptCBC(blocks, key) {

    let iv = blocks[0];
    let result = [];

    for (let i = 1; i < blocks.length; i++) {
        let x = aesDecrypt(blocks[i], key);
        let p = xor(x, iv);
        result.push(p);
        iv = blocks[i];
    }

    return result;
}

/* =========================================
   CFB MODE
========================================= */

function encryptCFB(blocks, key) {

    let iv = generateIV();
    let result = [iv];

    for (let b of blocks) {
        let o = aesEncrypt(iv, key);
        let c = xor(b, o);
        result.push(c);
        iv = c;
    }

    return result;
}

function decryptCFB(blocks, key) {

    let iv = blocks[0];
    let result = [];

    for (let i = 1; i < blocks.length; i++) {
        let o = aesEncrypt(iv, key);
        let p = xor(blocks[i], o);
        result.push(p);
        iv = blocks[i];
    }

    return result;
}

/* =========================================
   OFB MODE
========================================= */

function encryptOFB(blocks, key) {

    let iv = generateIV();
    let result = [iv];

    for (let b of blocks) {
        iv = aesEncrypt(iv, key);
        let c = xor(b, iv);
        result.push(c);
    }

    return result;
}

function decryptOFB(blocks, key) {

    let iv = blocks[0]; 
    let result = [];

    for (let i = 1; i < blocks.length; i++) {
        iv = aesEncrypt(iv, key);
        let p = xor(blocks[i], iv);
        result.push(p);
    }

    return result;
}

/* =========================================
   BASE64
========================================= */

function bytesToBase64(arr){
    let binary = "";
    for(let b of arr){
        binary += String.fromCharCode(b);
    }
    return btoa(binary);
}

function base64ToBytes(str){
    let binary = atob(str);
    let arr = [];
    for(let i=0;i<binary.length;i++){
        arr.push(binary.charCodeAt(i));
    }
    return arr;
}

/* =========================================
   HASH
========================================= */

function simpleHash(text){
    let hash = 0;
    for(let i=0;i<text.length;i++){
        hash = (hash + text.charCodeAt(i)) % 256;
    }
    return hash;
}

/* =========================================
   MAIN ENCRYPT
========================================= */

function encrypt() {

    let text = document.getElementById("text").value;
    let keyInput = document.getElementById("key").value;

    if(!keyInput){
        alert("Key tidak boleh kosong");
        return;
    }

    let key = keyToNumber(keyInput);

    let mode = document.getElementById("mode").value;
    let blocks = textToBytes(text);

    let result;

    if (mode === "ECB") result = encryptECB(blocks, key);
    if (mode === "CBC") result = encryptCBC(blocks, key);
    if (mode === "CFB") result = encryptCFB(blocks, key);
    if (mode === "OFB") result = encryptOFB(blocks, key);

    let format = document.getElementById("format").value;

    if(format === "decimal"){
        document.getElementById("result").value = result.join(" ");
    }

    if(format === "base64"){
        document.getElementById("result").value = bytesToBase64(result);
    }

    document.getElementById("hash").value = "Hash: " + simpleHash(text);
}

/* =========================================
   MAIN DECRYPT
========================================= */

function decrypt() {

    let text = document.getElementById("text").value;
    let keyInput = document.getElementById("key").value;

    if(!keyInput){
        alert("Key tidak boleh kosong");
        return;
    }

    let key = keyToNumber(keyInput);

    let mode = document.getElementById("mode").value;
    let format = document.getElementById("format").value;

    let blocks;

    if(format === "decimal"){
        blocks = text.split(" ").map(Number);
    }

    if(format === "base64"){
        blocks = base64ToBytes(text);
    }

    let result;

    if (mode === "ECB") result = decryptECB(blocks, key);
    if (mode === "CBC") result = decryptCBC(blocks, key);
    if (mode === "CFB") result = decryptCFB(blocks, key);
    if (mode === "OFB") result = decryptOFB(blocks, key);

    let resultText = bytesToText(result);
    document.getElementById("result").value = resultText;

    if(resultText.startsWith("data:image")){
        document.getElementById("resultImage").src = resultText;
    }
}

/* =========================================
   IMAGE INPUT 
========================================= */

document.getElementById("imageInput").addEventListener("change", function(e){

    let file = e.target.files[0];
    if(!file) return;

    let reader = new FileReader();

    reader.onload = function(event){

        let imageData = event.target.result;

        document.getElementById("preview").src = imageData;
        document.getElementById("text").value = imageData;

        document.getElementById("mainLayout").classList.add("split");
        moveOutput();

    };

    reader.readAsDataURL(file);

});

document.getElementById("fileInput").addEventListener("change", function(e){

    let file = e.target.files[0];
    if(!file) return;

    let reader = new FileReader();

    reader.onload = function(event){
        document.getElementById("text").value = event.target.result;
    };

    reader.readAsText(file);

});

/* =========================================
   PINDAHKAN OUTPUT
========================================= */

function moveOutput() {
    const left = document.getElementById("leftOutput");
    const right = document.getElementById("rightOutput");

    if (!right.contains(left)) {
        right.appendChild(left);
    }
} 
