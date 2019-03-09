// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>
#include <utilmoneystr.h>

#include <assert.h>

#include <chainparamsseeds.h>
#include <chainparamsimport.h>

#include <chainparams_mainnet.h>
#include <chainparams_testnet.h>
#include <chainparams_regtest.h>

int64_t CChainParams::GetCoinYearReward(int64_t nTime, CAmount nMoneySupply) const
{
    static const int64_t nSecondsInYear = 365 * 24 * 60 * 60;

    int64_t coinYearReward = nCoinYearReward; // Use default of 1%

    if (strNetworkID != "regtest")
    {
        // Y1 5%, YN 1%
        int64_t nYearsSinceGenesis = (nTime - genesis.nTime) / nSecondsInYear;

        if (nYearsSinceGenesis == 0)
            coinYearReward = 5 * CENT; // 5% for the first year
    };

    // No reward once the max money supply has been reached.
    return nMoneySupply < MAX_MONEY ? coinYearReward : 0;
};

int64_t CChainParams::GetProofOfStakeReward(const CBlockIndex *pindexPrev, int64_t nFees) const
{
    int64_t nSubsidy;

    nSubsidy = (pindexPrev->nMoneySupply / COIN) *
        GetCoinYearReward(pindexPrev->nTime, pindexPrev->nMoneySupply) /
        (365 * 24 * (60 * 60 / nTargetSpacing));

    if (LogAcceptCategory(BCLog::POS) && gArgs.GetBoolArg("-printcreation", false))
        LogPrintf("GetProofOfStakeReward(): create=%s\n", FormatMoney(nSubsidy).c_str());

    return nSubsidy + nFees;
};

bool CChainParams::CheckImportCoinbase(int nHeight, uint256 &hash) const
{
    for (auto &cth : Params().vImportedCoinbaseTxns)
    {
        if (cth.nHeight != (uint32_t)nHeight)
            continue;

        if (hash == cth.hash)
            return true;
        return error("%s - Hash mismatch at height %d: %s, expect %s.", __func__, nHeight, hash.ToString(), cth.hash.ToString());
    };

    return error("%s - Unknown height.", __func__);
};

const DevFundSettings *CChainParams::GetDevFundSettings(int64_t nTime) const
{
    for (size_t i = vDevFundSettings.size(); i-- > 0; )
    {
        if (nTime > vDevFundSettings[i].first)
            return &vDevFundSettings[i].second;
    };

    return nullptr;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn) const
{
    for (auto &hrp : bech32Prefixes)
    {
        if (vchPrefixIn == hrp)
            return true;
    };

    return false;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k)
    {
        auto &hrp = bech32Prefixes[k];
        if (vchPrefixIn == hrp)
        {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        };
    };

    return false;
};

bool CChainParams::IsBech32Prefix(const char *ps, size_t slen, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k)
    {
        auto &hrp = bech32Prefixes[k];
        size_t hrplen = hrp.size();
        if (hrplen > 0
            && slen > hrplen
            && strncmp(ps, (const char*)&hrp[0], hrplen) == 0)
        {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        };
    };

    return false;
};


static CBlock CreateGenesisBlockRegTest(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

    CMutableTransaction txNew;
    txNew.nVersion = EFIN_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputsRegtest);
    for (size_t k = 0; k < nGenesisOutputsRegtest; ++k)
    {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = regTestOutputs[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(regTestOutputs[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    };

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = EFIN_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockTestNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

    CMutableTransaction txNew;
    txNew.nVersion = EFIN_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputsTestnet);
    for (size_t k = 0; k < nGenesisOutputsTestnet; ++k)
    {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = genesisOutputsTestnet[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(genesisOutputsTestnet[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    };

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = EFIN_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockMainNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "BTC 000000000000000000c679bc2209676d05129834627c7b1c02d1018b224c6f37";

    CMutableTransaction txNew;
    txNew.nVersion = EFIN_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);

    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputs);
    for (size_t k = 0; k < nGenesisOutputs; ++k)
    {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = genesisOutputs[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(genesisOutputs[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    };

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = EFIN_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}



void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 1510272000; // 2017-11-10 00:00:00 UTC
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0x3AFE130E00; // 9999 TODO: lower

        consensus.powLimit = uint256S("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        consensus.nMinRCTOutputDepth = 12;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xef;
        pchMessageStart[3] = 0xb4;
        nDefaultPort = 40627;
        nBIP44ID = (1 << 31) + 3714; // 3714' 0x80000e82;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 225;   // 225 * 2 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        // No need to import coinbase transactions.
        // AddImportHashesMain(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 100000;

        // Create MainNet genesis block
        genesis = CreateGenesisBlockMainNet(1554076800, 17205864, 0x1f0000ff); // 2019-03-20 13:00:00
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0000001d09377200402656078e4b720177ddf7351b8849a473c018e07f779966"));
        assert(genesis.hashMerkleRoot == uint256S("0x8d8f9bf4c3ec9e84466e473276e8ab40cecdf5f318c7fb9e6e1b282158d755a1"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x9d4ea48951dd175154f12b8e2a43cc9cdfc72c4431b7693361f5be4ff5178549"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        // TODO: Add eFin DNS seeds here for *mainnet*. i.e.: vSeeds.emplace_back("hostname");

        base58Prefixes[PUBKEY_ADDRESS]     = {0x21}; // E
        base58Prefixes[SCRIPT_ADDRESS]     = {0x3c};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x39};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x3d};
        base58Prefixes[SECRET_KEY]         = {0x5c};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x69, 0x6e, 0x82, 0xd1}; // Efub
        base58Prefixes[EXT_SECRET_KEY]     = {0x01, 0x1c, 0x34, 0x88}; // Efpv
        base58Prefixes[STEALTH_ADDRESS]    = {0x14};
        base58Prefixes[EXT_KEY_HASH]       = {0x4b}; // X
        base58Prefixes[EXT_ACC_HASH]       = {0x17}; // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("ph","ph"+2);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("pr","pr"+2);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("pl","pl"+2);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("pj","pj"+2);
        bech32Prefixes[SECRET_KEY].assign           ("px","px"+2);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("pep","pep"+3);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("pex","pex"+3);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("ps","ps"+2);
        bech32Prefixes[EXT_KEY_HASH].assign         ("pek","pek"+3);
        bech32Prefixes[EXT_ACC_HASH].assign         ("pea","pea"+3);

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            // Add checkpoint data as the blockchain grows.
        };

        chainTxData = ChainTxData {
            // Add tx data as the blockchain grows.
        };
    }

    void SetOld()
    {
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = true; // TODO: clear for next testnet
        consensus.nPaidSmsgTime = 0;

        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        consensus.nMinRCTOutputDepth = 12;

        pchMessageStart[0] = 0x08;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x05;
        pchMessageStart[3] = 0x0b;
        nDefaultPort = 40827;
        nBIP44ID = (1 << 31) + 3715; // 3715' 0x80000e83;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 20;    // 20 * 2 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        // No need to import coinbase transactions.
        // AddImportHashesTest(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlockTestNet(1554076800, 85833, 0x1f00ffff);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0000c5fb108be9ccb0618e01357f652fc66f20ee035fcd686e1226028669b9bf"));
        assert(genesis.hashMerkleRoot == uint256S("0x4da1df10a3caba657d726fa521146ec28ac80307a555a9ccae8265684d8fc66e"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x9c8c9b404a86d5f6624be9994bfd7674a38053f5326b84f2e665b78db25fbe43"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        /*
        TODO: Add eFin DNS seeds here for *testnet*. i.e.: vSeeds.emplace_back("hostname");
        */

        base58Prefixes[PUBKEY_ADDRESS]     = {0x5c}; // e
        base58Prefixes[SCRIPT_ADDRESS]     = {0x7a};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0xfe}; // e
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04, 0x32, 0x4d, 0xe3}, // tfub
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x32, 0x46, 0x7f}, // tfpv
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph","tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr","tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl","tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj","tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx","tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep","tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex","tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps","tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek","tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea","tpea"+4);

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            // Add checkpoint data as the blockchain grows (testnet).
        };

        chainTxData = ChainTxData{
            // Add tx data as the blockchain grows (testnet).
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0;

        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nMinRCTOutputDepth = 1;

        pchMessageStart[0] = 0x09;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0x06;
        pchMessageStart[3] = 0x0c;
        nDefaultPort = 11938;
        nBIP44ID = 0x80000001;


        nModifierInterval = 2 * 60;     // 2 minutes
        nStakeMinConfirmations = 12;
        nTargetSpacing = 5;             // 5 seconds
        nTargetTimespan = 16 * 60;      // 16 mins
        nStakeTimestampMask = 0;

        SetLastImportHeight();

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlockRegTest(1523355070, 0, 0x207fffff);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x610b31816d82418e9aa1ce089e5de6fab79f09a57443c5811c024a22eb1e7f81"));
        assert(genesis.hashMerkleRoot == uint256S("0x3c6cd4645fbe2209af41faf1688f336c767764d1d11b067ea1217c79fcd3ecaa"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x9b1020f11cc6c5dd336826413c9995fd284fe2e26af571aa2aafe31e8bbfde3a"));


        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            // Add checkpoint data as the blockchain grows (regtest).
        };

        base58Prefixes[PUBKEY_ADDRESS]     = {0x5c}; // e
        base58Prefixes[SCRIPT_ADDRESS]     = {0x7a};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0xfe}; // e
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04, 0x32, 0x4d, 0xe3}, // tfub
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x32, 0x46, 0x7f}, // tfpv
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph","tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr","tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl","tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj","tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx","tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep","tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex","tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps","tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek","tpek"+4);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpea","tpea"+4);

        bech32_hrp = "bcrt";

        chainTxData = ChainTxData{
            // Add tx data as the blockchain grows (regtest).
        };
    }

    void SetOld()
    {
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams *pParams() {
    return globalChainParams.get();
};

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}


void SetOldParams(std::unique_ptr<CChainParams> &params)
{
    if (params->NetworkID() == CBaseChainParams::MAIN)
        return ((CMainParams*)params.get())->SetOld();
    if (params->NetworkID() == CBaseChainParams::REGTEST)
        return ((CRegTestParams*)params.get())->SetOld();
};

void ResetParams(std::string sNetworkId, bool fEfinModeIn)
{
    // Hack to pass old unit tests
    globalChainParams = CreateChainParams(sNetworkId);
    if (!fEfinModeIn)
    {
        SetOldParams(globalChainParams);
    };
};

/**
 * Mutable handle to regtest params
 */
CChainParams &RegtestParams()
{
    return *globalChainParams.get();
};

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

