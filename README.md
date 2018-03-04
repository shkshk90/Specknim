# Specknim 

Specknim is a commandline tool written in nim. It implements the [Speck cipher](https://eprint.iacr.org/2013/404).

## Usage

Specknim can be used to encrypt or decrypt text. Both text and keys can be provided either as command-line argument or as a file. 
Command-line properties are as follows:

```
Usage: specknim   [-[e|d]] [-hv]
                  [-s 'text'] [-f text file]
                  [-k 'key'] [-K key file]
  
  Command summary:
      -e                  Encrypt
      -d                  Decrypt
      -h                  This help text
      -v                  Print version number
      -s                  Plain or cipher text
      -f                  File containing the text
      -k                  Key string
      -K                  File containing the key
```

### Examples
Basic usage:
```
specknim -e -s 'plain text' -k 'secret'
```

Decryption:
```
specknim -d -s E3AE41153FA54FB1119C79CC0F11723E -k 'secret'
```

File encryption:
```
specknim -e -f ~/plaintext.txt -k 'secret'
```


### Compilation

Specknim can be compiled using nim:
```
nim c -d:release src/specknim.nim
```
It is tried with nim 0.18.0 under macOS 10.13.3. It should work fine under Linux. 



## DISCLAIMER

This software is by no means secure. No guarantees what so ever on the security it provides.
First, the cipher is not well tested by academia.
Second, no measures were taken against side-channel attacks.

This software was created as a hobby and is not guaranteed to provide any security.


## License

This project is licensed under the BSD 2-Clause "Simplified" License - see the [LICENSE](LICENSE) file for details


