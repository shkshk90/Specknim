#[
    Simple command line tool for encrypting and decrypting
    files using the Speck cipher.

    Reference paper:
      https://eprint.iacr.org/2013/404.pdf

    Author:
      Samuel Bassaly
]#


import os, parseopt, sequtils, strutils


const
  blockSize         = 128
  keySize           = 256
  wordSize          = 64
  keyWords          = 4
  alpha             = 8
  beta              = 3
  rounds            = 34

  blockBytes        = blockSize div 8
  wordBytes         = wordSize div 8

  mask              = 255
  cipherRounds      = rounds - 1

  usage             = """
Usage: speck  [-[e|d]] [-hv]
              [-s 'text'] [-f text file]
              [-k 'key'] [-K key file] """
  help              = usage & """
  Command summary:
      -e                  Encrypt
      -d                  Decrypt
      -h                  This help text
      -v                  Print version number
      -s                  Plain or cipher text
      -f                  File containing the text
      -k                  Key string
      -K                  File containing the key """
  version           = """
Speck version 0.1 """


template ror(x: uint64): uint64 =
  (x shr alpha) or (x shl (64 - alpha))

template rol(x: uint64): uint64 =
  (x shl beta) or (x shr (64 - beta))

template iror(x: uint64): uint64 =
  (x shr beta) or (x shl (64 - beta))

template irol(x: uint64): uint64 =
  (x shl alpha) or (x shr (64 - alpha))

template printUsage() =
  echo usage
  quit(QuitSuccess)

template printHelp() =
  echo help
  quit(QuitSuccess)

template printVersion() =
  echo version
  quit(QuitSuccess)






proc expandKeys(key: array[keyWords, uint64]): array[rounds, uint64]  =
  const expansionRounds = rounds - 2
  const m = keyWords

  result[0] = key[0]

  var temp: array[expansionRounds + m, uint64]

  for i in countup(1, keyWords - 1):
    temp[i - 1] = key[i]

  for i in countup(0, expansionRounds):
    let sAlpha = ror temp[i]
    let sBeta  = rol result[i]

    temp[i + m - 1] = (result[i] + sAlpha) xor uint64(i)
    result[i + 1] = sBeta xor temp[i + m - 1]


proc encryptOneBlock(plainText: array[2, uint64], expandedKey: array[rounds, uint64]): array[2, uint64] =
  var x = plainText[1]
  var y = plainText[0]

  for i in countup(0, cipherRounds):
    let sx = ror x
    let sy = rol y

    x = (sx + y) xor expandedKey[i]
    y = sy xor x

  result[1] = x
  result[0] = y


proc decryptOneBlock(cipherText: array[2, uint64], expandedKey: array[rounds, uint64]): array[2, uint64] =
  var x = cipherText[1]
  var y = cipherText[0]

  for i in countdown(cipherRounds, 0):
    let xy = x xor y
    let xk = x xor expandedKey[i]

    let sxy = iror xy
    let sxky = xk - sxy

    x = irol sxky
    y = sxy

  result[1] = x
  result[0] = y


proc generateKeyBlocks(keyString: string): array[keyWords, uint64] =
  let slen = keyString.len

  proc maxVal(max: int, val: int): int {.inline.} =
    if val > max:
      result = max
    else:
      result = val

  if slen == 0:
    result = [0'u64, 0'u64, 0'u64, 0'u64]
  else:
    let en = maxval(8, slen)
    var n = 0'u64

    for i in 0..<en:
      let c = uint64(keyString[i])
      let s = i * 8

      n = n or (c shl s)

    result[0] = n

  if slen > 8:
    let en = maxval(16, slen)
    var n = 0'u64

    for i in 8..<en:
      let c = uint64(keyString[i])
      let s = (i - 8) * 8

      n = n or (c shl s)

    result[1] = n

  if slen > 16:
    let en = maxval(24, slen)
    var n = 0'u64

    for i in 16..<en:
      let c = uint64(keyString[i])
      let s = (i - 16) * 8

      n = n or (c shl s)

    result[2] = n

  if slen > 24:
    let en = maxval(32, slen)
    var n = 0'u64

    for i in 24..<en:
      let c = uint64(keyString[i])
      let s = (i - 24) * 8

      n = n or (c shl s)

    result[3] = n


proc generateTextBlocks(text: var string): seq[array[2, uint64]] =
  let slen = text.len
  if slen == 0:
    result = nil
    return

  let blen = ((slen - 1) div blockBytes) + 1
  let diff = blockBytes - (slen mod blockBytes)

  result = newSeq[array[2, uint64]](blen)

  if diff < blockBytes:
    for i in 0..<diff:
      text.add char(0)

  for i in 0..<blen: #countup(0, blen - 2):
    let st = i * blockBytes
    let md = st + wordBytes
    let en = st + blockBytes

    var n = 0'u64

    for j in st..<md:
      let c = uint64(text[j])
      let s = (j - st) * 8

      n = n or (c shl s)

    result[i][0] = n
    n = 0

    for j in md..<en:
      let c = uint64(text[j])
      let s = (j - md) * 8

      n = n or (c shl s)

    result[i][1] = n


proc generateStringFromBlocks(textBlocks: seq[array[2, uint64]], decrypt: bool = false): string =
  proc blockToString(blk: array[2, uint64]): string =
    result = ""
    block numbers:
      for i in 0..1:
        let wrd = blk[i]
        for j in 0..<wordBytes:
          let s = j * 8
          let c = (wrd shr s) and mask
          let cc = char(c)

          if decrypt and c == 0:
            break numbers

          result = result & cc

  let stringBlocks = map(textBlocks, blockToString)
  result = foldl(stringBlocks, a & b)


proc readFromFile(path: string): string {.raises: [IOError].}  =
  try:
    result = readFile(path)
  except IOError:
    echo getCurrentExceptionMsg()
    echo ""
    echo usage
    quit(QuitFailure)

  result = result[0..^2]      # Removes EOF


proc encrypt(plaintext: string, key: string): string =
  var plaintext           = plaintext

  let plaintextBlocks     = generateTextBlocks plaintext
  let keyBlocks           = generateKeyBlocks key
  let expandedKey         = expandKeys keyBlocks

  let ciphertextBlocks    = map(plaintextBlocks,
  proc(blk: array[2, uint64]): array[2, uint64] = result = encryptOneBlock(blk, expandedKey))

  result = generateStringFromBlocks ciphertextBlocks


proc decrypt(ciphertext: string, key: string): string =
  assert(ciphertext.len mod blockBytes == 0)

  var ciphertext          = ciphertext

  let ciphertextBlocks    = generateTextBlocks ciphertext
  let keyBlocks           = generateKeyBlocks key
  let expandedKey         = expandKeys keyBlocks

  let plaintextBlocks    = map(ciphertextBlocks,
  proc(blk: array[2, uint64]): array[2, uint64] = result = decryptOneBlock(blk, expandedKey))

  result = generateStringFromBlocks(plaintextBlocks, true)


proc main() =
  if paramCount() < 1:
    printUsage()

  var
    edFlag              = false
    textFlag            = false
    keyFlag             = false
    encryptText         = false
    lastOpt             = '0'

  var cpText:         string
  var encryptionKey:  string
  var result:         string

  var p = initOptParser()
  for kind, key, _ in p.getOpt():
    case kind
    of cmdShortOption:
      lastOpt = key[0]

      case key[0]:
      of 'd', 'e':
        if edFlag:
          printUsage()
        edFlag = true
        encryptText = key[0] == 'e'
      of 's', 'f':
        if textflag:
          printUsage()
        textflag = true
      of 'k', 'K':
        if keyFlag:
          printUsage()
        keyFlag = true
      of 'v':
        if paramCount() == 1:
          printVersion()
        else:
          printUsage()
      of 'h':
        if paramCount() == 1:
          printHelp()
        else:
          printUsage()
      else:
        printUsage()

    of cmdArgument:
      case lastOpt
      of 's':
        cpText = key
      of 'f':
        cpText = readFromFile key
      of 'k':
        encryptionKey = key
      of 'K':
        encryptionKey = readFromFile key
      else:
        printUsage()

      lastOpt = '0'

    of cmdLongOption:
      printUsage()
    of cmdEnd:
      assert false


  if edFlag and textFlag and keyFlag:
    if cpText.len == 0:
      echo "Error: empty text"
      echo ""
      echo usage
      quit(QuitFailure)

    if encryptionKey.len == 0:
      echo "Error: empty key"
      echo ""
      echo usage
      quit(QuitFailure)

    if encryptText:
      result = encrypt(cpText, encryptionKey)
    else:
      result = decrypt(cpText, encryptionKey)
  else:
    printUsage()

  echo result


main()
