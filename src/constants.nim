const
  blockSize*         = 128
  keySize*           = 256
  wordSize*          = 64
  keyWords*          = 4
  alpha*             = 8
  beta*              = 3
  rounds*            = 34

  keyBytes*          = keySize    div 8
  blockBytes*        = blockSize  div 8
  wordBytes*         = wordSize   div 8

  mask*              = 255
  cipherRounds*      = rounds - 1

  usage*             = """
Usage: speck  [-[e|d]] [-hv]
              [-s 'text'] [-f text file]
              [-k 'key'] [-K key file] """
  help*              = usage & """
  Command summary:
      -e                  Encrypt
      -d                  Decrypt
      -h                  This help text
      -v                  Print version number
      -s                  Plain or cipher text
      -f                  File containing the text
      -k                  Key string
      -K                  File containing the key """
  version*           = """
Speck version 0.1 """
