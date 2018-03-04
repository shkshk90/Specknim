#[
    Simple command line tool for encrypting and decrypting
    files using the Speck cipher.

    Reference paper:
      https://eprint.iacr.org/2013/404.pdf

    Author:
      Samuel Bassaly
]#


import os, parseopt, sequtils, strutils
import constants, macros, speckutils



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


proc encrypt(plaintext: string, key: string): string =
  var plaintext           = plaintext

  let plaintextBlocks     = generateTextBlocks plaintext
  let keyBlocks           = generateKeyBlocks key
  let expandedKey         = expandKeys keyBlocks

  let ciphertextBlocks    = map(plaintextBlocks,
  proc(blk: array[2, uint64]): array[2, uint64] = result = encryptOneBlock(blk, expandedKey))

  result = generateStringFromBlocks ciphertextBlocks
  result = result.toHex


proc decrypt(ciphertext: string, key: string): string =
  assert(ciphertext.len mod blockBytes == 0)

  var ciphertext          = ciphertext.parseHexStr

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
