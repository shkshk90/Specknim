import constants, sequtils, strutils


proc generateKeyBlocks*(keyString: string): array[keyWords, uint64] =
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


proc generateTextBlocks*(text: var string): seq[array[2, uint64]] =
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


proc generateStringFromBlocks*(textBlocks: seq[array[2, uint64]], decrypt: bool = false): string =
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


proc readFromFile*(path: string): string  =
  try:
    result = readFile(path)
  except:
    echo getCurrentExceptionMsg()
    echo ""
    echo usage
    quit(QuitFailure)

  result = result[0..^2]      # Removes EOF
