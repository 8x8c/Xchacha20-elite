# xchacha20 elite

AES version of this app  https://github.com/8x8c/AES-elite




Read this readme and any file in the /docs directory

The goal- make the best cli Xchacha-poly1305 encryption app possible that is easiest to use and is the most secure, and make it password based. 

## usage

./[whatever you named the app] [input file]

it will then prompt you for a password. 

encrypts the file in place (overwrites it) 

In memory processing only for reliability. Modern machines have plenty of ram. 

For a gaming computer , like an i900k with 64 gm ram, you can crank up the argon2 settings way up to make the
password about impossible to brute force. 



# Demo Screenshots
I will keep the app updated to make the strongest encryption possible. As a demo, make a file called test.html with all "a" charachters like aaaaaaaaaaaaaaaaaaaaaaaa  

then encrypt the file using the password "a"  and open the file in any web browser  and you will be able to see that the  encrypted file will be incredibly random. 

That is the WORST case - just one char as the password. So imagine how good it will encrypt with a proper password!! 

![1](https://github.com/user-attachments/assets/9bbf7952-efdf-43d7-adbb-4fb3ccb6ba80)



![2](https://github.com/user-attachments/assets/e5b22d84-c635-4093-b007-ce5e877d95e4)


The MYENCAPP that you see at thestart of the cyphertext is the magic header. It is injected into they cyphertext so the app can automatically determine if it should be
encrypted or decrypted. And with aes the nonce in injected too. SO make sure if your file is an executable, to ZIP it before encrypting. Encrypting/decrypting an executable could possibly change a byte at the start of it, which could make executable not run. So a standard practice is to zip executables for safer encryption. 
