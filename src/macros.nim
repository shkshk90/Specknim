template ror*(x: uint64): uint64 =
  (x shr alpha) or (x shl (64 - alpha))

template rol*(x: uint64): uint64 =
  (x shl beta) or (x shr (64 - beta))

template iror*(x: uint64): uint64 =
  (x shr beta) or (x shl (64 - beta))

template irol*(x: uint64): uint64 =
  (x shl alpha) or (x shr (64 - alpha))


template printUsage*() =
  echo usage
  quit(QuitSuccess)

template printHelp*() =
  echo help
  quit(QuitSuccess)

template printVersion*() =
  echo version
  quit(QuitSuccess)
