#ifndef BITCOIN_CHAINPARAMS_REGTEST_H
#define BITCOIN_CHAINPARAMS_REGTEST_H

#include <utility>
#include <cstddef>
#include "amount.h"

extern const std::pair<const char*, CAmount> regTestOutputs[];
extern const size_t nGenesisOutputsRegtest;

#endif
