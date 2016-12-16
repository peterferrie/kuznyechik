;
;  Copyright © 2016 Odzhan, Peter Ferrie. All Rights Reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions are
;  met:
;
;  1. Redistributions of source code must retain the above copyright
;  notice, this list of conditions and the following disclaimer.
;
;  2. Redistributions in binary form must reproduce the above copyright
;  notice, this list of conditions and the following disclaimer in the
;  documentation and/or other materials provided with the distribution.
;
;  3. The name of the author may not be used to endorse or promote products
;  derived from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
;  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
;  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
;  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;  POSSIBILITY OF SUCH DAMAGE.
;
; -----------------------------------------------
; Kuznechik block cipher in x86 assembly
;
; size: 662
;
; global calls use cdecl convention
;
; -----------------------------------------------


    bits 32
   
%define KUZ_ROUNDS 10
   
    %ifndef BIN
      global kuz_setkeyx
      global _kuz_setkeyx
      
      global kuz_encryptx
      global _kuz_encryptx
    %endif

; key setup
kuz_setkeyx:
_kuz_setkeyx:
    pushad
    mov    edi, [esp+32+4]   ; ebx=kuz context
    mov    esi, [esp+32+8]   ; esi=key
    mov    ebp, edi
    
    xor    eax, eax          ; eax=0
    cdq                      ; edx=0
    call   kuz_init
    
    push   32
    pop    ecx
    ; copy key to context
    pushad
    rep    movsb
    popad
    ; copy 256-bit key to local buffer
    pushad                   ; allocate 32 bytes for x
    mov    edi, esp          ; edi=x
    push   edi
    rep    movsb
    pop    edi
    
    pushad                   ; allocate 32 bytes for c,z
    mov    ebx, esp          ; ebx=z
    lea    esi, [ebx+16]     ; esi=c
    ; do 32 rounds
ksk_l0:
    inc    edx
    cmp    dl, 32
    ja     ksk_l3
    
    push   edi               ; save x
    mov    edi, esi
    xor    eax, eax
    mov    cl, 16
    rep    stosb             ; memset (&c.b[0], 0, 16);
    mov    [esi+15], dl      ; c.b[15] = i;
    
    mov    edi, esi
    call   kuz_lt            ; kuz_lt(&c, KUZ_ENCRYPT);
    pop    edi
ksk_l1:
    mov    al, [edi+ecx]     ; al=x.b[j]
    xor    al, [esi+ecx]     ; ^= c.b[j]
    mov    [ebx+ecx], al 
    inc    ecx
    cmp    cl, 16    
    jnz    ksk_l1
    
    xor    ecx, ecx
    xchg   esi, ebx     ; XCHG(c, z)
    xchg   edi, ebp     ; XCHG(x, kuz)
    call   kuz_subbytes ; kuz_subbytes(&z, kuz, KUZ_ENCRYPT);
    call   kuz_lt       ; kuz_lt(&z, KUZ_ENCRYPT);
    xchg   esi, ebx     ; XCHG(c, z)
    xchg   edi, ebp     ; XCHG(x, kuz)

ksk_l2:
    mov    al, [edi+ecx+16] ; z.b[j] ^= x.b[16+j];
    xor    [ebx+ecx], al
    inc    ecx
    cmp    cl, 16
    jnz    ksk_l2
    
    ; memcpy (&x.b[16], &x.b[0], 16);
    pushad
    mov    esi, edi
    add    edi, ecx
    rep    movsb
    popad
    
    ; memcpy (&x.b[0], &z.b[0], 16);
    pushad
    mov    esi, ebx
    rep    movsb
    popad
    
    test   dl, 7
    jnz    ksk_l0
    
    ; memcpy (&kuz->k[(i >> 2)].b[0], &x.b[0], 32);
    pushad
    add    ecx, ecx
    shr    edx, 2
    shl    edx, 4
    mov    esi, edi
    lea    edi, [ebp+edx]
    rep    movsb
    popad
    jmp    ksk_l0
ksk_l3:
    popad
    popad
    popad
    ret
    
; encrypt/decrypt a block
kuz_encryptx:
_kuz_encryptx:
    pushad
    lea    esi, [esp+32+4]
    lodsd
    xchg   eax, edi          ; edi=key
    lodsd
    push   eax               ; save blk
    lodsd
    cdq                      ; edx=0
    xchg   eax, ecx          ; ecx=enc
    pop    esi               ; esi=blk
    call   load_func
    
; key whitening
; esi = w
; edi = key
; edx = round
kuz_whiten:
    pushad
    mov    cl, 4
    shl    edx, cl
w_l0:
    mov    eax, [edi+edx]     ; get 4 bytes of key
    xor    [esi], eax         ; xor state
    cmpsd
    loop   w_l0
    popad
    ret
    
; linear transformation
; esi = w
; ecx = enc
kuz_lt:
    pushad
    jmp    lt_l6
lt_l0:
    pop    ebx
    push   16
    pop    edi               ; 16 rounds
    lea    ebp, [ebx+edi]    ; ebp = kuz_mul_gf256
lt_l1:
    pushad
    xor    edi, edi
    test   ecx, ecx
    jnz    lt_l3
    push   14
    pop    edi
    
    mov    al, [esi+15]      ; al = w->b[15]
lt_l2:
    mov    cl, [ebx+edi]     ; cl = kuz_lvec[i]
    mov    dl, [esi+edi]     ; dl = w->b[i]
    mov    [esi+edi+1], dl   ; w->b[i + 1] = dl
    call   ebp
    dec    edi
    jns    lt_l2
    
    mov    [esi], al
    jmp    lt_l5
lt_l3:
    mov    al, [esi]         ; al = w->b[0]
lt_l4:
    mov    cl, [ebx+edi]     ; cl = kuz_lvec[i]
    mov    dl, [esi+edi+1]   ; dl = w->b[i+1]
    mov    [esi+edi], dl     ; w->b[i] = dl
    call   ebp
    inc    edi
    cmp    edi, 15
    jnz    lt_l4
    
    mov    [esi+15], al      ; w->b[15] = x
lt_l5:
    popad
    dec    edi
    jnz    lt_l1
    popad
    ret
lt_l6:
    call   lt_l0
    db 0x94, 0x20, 0x85, 0x10 
    db 0xC2, 0xC0, 0x01, 0xFB
    db 0x01, 0xC0, 0xC2, 0x10
    db 0x85, 0x20, 0x94, 0x01
; poly multiplication 
; mod p(x) = x^8 + x^7 + x^6 + x + 1 
kuz_mul_gf256:
    push   eax
    xor    eax, eax          ; z=0
    jecxz  mgf_l3            ; while (y)
mgf_l0:
    test   cl, 1             ; if (y & 1)
    je     mgf_l1
    xor    al, dl            ; z ^= x
mgf_l1:
    add    dl, dl            ; x <<= 1
    jnc    mgf_l2
    xor    dl, 0xC3
mgf_l2:
    shr    ecx, 1            ; y >>= 1
    jnz    mgf_l0
mgf_l3:
    xor    byte[esp], al
    pop    eax
    ret
    
; substitute bytes
; esi = w
; ecx = enc
kuz_subbytes:
    pushad
    mov    dl, 255
    inc    edx
    lea    ebx, [edi+edx]    ; ebx = key->pi
    test   ecx, ecx          ; KUZ_ENCRYPT?
    mov    cl, 16
    jz     sbs_l0
    add    ebx, edx          ; ebx = key->pi_inv
sbs_l0:
    mov    edi, esi
sbs_l1:
    lodsb
    xlatb                    ; 
    stosb                    
    loop   sbs_l1
    popad
    ret
load_func:
    pop    ebx
    lea    eax, [ebx + (kuz_lt - kuz_whiten)]
    lea    ebp, [eax + (kuz_subbytes - kuz_lt)]
    
    jecxz  kuz_enc
    xchg   eax, ebp
    mov    dl, KUZ_ROUNDS
kuz_dec:
    dec    edx
    call   ebx ; kuz_whiten
    test   edx, edx
    jz     kuz_enc_exit
    
    call   ebp ; kuz_lt
    call   eax ; kuz_subbytes
    
    jmp    kuz_dec
kuz_enc:
    call   ebx ; kuz_whiten
    
    inc    edx
    cmp    dl, KUZ_ROUNDS
    jz     kuz_enc_exit
    
    call   ebp ; kuz_subbytes
    call   eax ; kuz_lt
    
    jmp    kuz_enc
    
kuz_enc_exit:
    popad
    ret
 
; initialize sbox tables 
; edi = key context
kuz_init:
    pushad
    xor    eax, eax
    cdq
    inc    dh
    add    edi, edx          ; edi = key->pi
    lea    esi, [edi+edx]    ; esi = key->pi_inv
    jmp    init_sbox
load_sbox:
    pop    ebx               ; ebx = kuz_pi
sbox_loop:
    mov    al, dl            ; al = i
    xlatb                    ; al = kuz_pi[i]
    stosb                    ; key->pi[i] = al
    mov    [esi+eax], dl     ; key->pi_inv[kuz_pi[i]] = i
    inc    dl
    jnz    sbox_loop
    popad
    ret
init_sbox:
    call   load_sbox
; The S-Box from section 5.1.1
kuz_pi:
  db   0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,   ; 00..07
  db   0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,   ; 08..0F
  db   0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,   ; 10..17
  db   0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,   ; 18..1F
  db   0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,   ; 20..27
  db   0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,   ; 28..2F
  db   0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,   ; 30..37
  db   0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,   ; 38..3F
  db   0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,   ; 40..47
  db   0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,   ; 48..4F
  db   0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,   ; 50..57
  db   0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,   ; 58..5F
  db   0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,   ; 60..67
  db   0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,   ; 68..6F
  db   0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,   ; 70..77
  db   0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,   ; 78..7F
  db   0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,   ; 80..87
  db   0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,   ; 88..8F
  db   0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,   ; 90..97
  db   0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,   ; 98..9F
  db   0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,   ; A0..A7
  db   0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,   ; A8..AF
  db   0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,   ; B0..B7
  db   0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,   ; B8..BF
  db   0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,   ; C0..C7
  db   0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,   ; C8..CF
  db   0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,   ; D0..D7
  db   0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,   ; D8..DF
  db   0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,   ; E0..E7
  db   0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,   ; E8..EF
  db   0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,   ; F0..F7
  db   0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6,   ; F8..FF
  
  