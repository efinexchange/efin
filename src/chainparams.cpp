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

int64_t CChainParams::GetCoinYearReward(int64_t nTime) const
{
    static const int64_t nSecondsInYear = 365 * 24 * 60 * 60;

    if (strNetworkID != "regtest")
    {
        // Y1 5%, Y2 4%, Y3 3%, Y4 2%, ... YN 2%
        int64_t nYearsSinceGenesis = (nTime - genesis.nTime) / nSecondsInYear;

        if (nYearsSinceGenesis >= 0 && nYearsSinceGenesis < 3)
            return (5 - nYearsSinceGenesis) * CENT;
    };

    return nCoinYearReward;
};

int64_t CChainParams::GetProofOfStakeReward(const CBlockIndex *pindexPrev, int64_t nFees) const
{
    int64_t nSubsidy;

    nSubsidy = (pindexPrev->nMoneySupply / COIN) * GetCoinYearReward(pindexPrev->nTime) / (365 * 24 * (60 * 60 / nTargetSpacing));

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

const std::pair<const char*, CAmount> regTestOutputs[] = {
    // TODO: Define official initial coin supply.
    // inner moral wet catch timber high now wet raise onion size tooth merit night movie chalk vote benefit hour card crime ask begin confirm
    std::make_pair("cfbc902d62a2197b6b87f0fce07d15a731dc6392", 10000 * COIN),
    // strike next install blame budget comfort wasp radar envelope yellow ecology onion edit live grass asthma worry obscure shy wing cabin mobile trust garden
    std::make_pair("1c5088a074d42330aa12b54956567ec46212140f", 15000 * COIN)
};
const size_t nGenesisOutputsRegtest = sizeof(regTestOutputs) / sizeof(regTestOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputs[] = {
    // TODO: Define official initial coin supply.
    // kit youth enroll gravity inform coil life response over collect shrimp fashion desk million differ style october hill first fiscal reform among fiscal word
    std::make_pair("03217fe1e5f895420b2b30cb5dc4ef990a5f8994", 200 * COIN),
    std::make_pair("b903201a6480907984b74dde59e71149c0c4503f", 200 * COIN),
    std::make_pair("9bd7f2482eff85a1b8a2963534802331068a4c29", 200 * COIN),
    std::make_pair("520c94fac3a526534883c59ab4646010f8da8dc7", 200 * COIN),
    std::make_pair("c876a9c62b53d8e331932fb5ddc2c31db225282c", 200 * COIN),
    std::make_pair("0a83705e2013193cbdfd4c9bd669a6562f9e146b", 200 * COIN),
    std::make_pair("e80c22fb2652e5fb5b848a4d4ea6f0ec7ba04488", 200 * COIN),
    std::make_pair("14406d279c05b1f28847fb89ac4af625a80517df", 200 * COIN),
    std::make_pair("52ce34947ba84f5ef6e7a20bd237acb4b8a55284", 200 * COIN),
    std::make_pair("15e0cdfeedc8ded5ddd1ab7155039b8a92d2559b", 200 * COIN),

    // mother other range giant note choose remember shock reason upset able marble keep hockey chronic news bicycle extend price bargain turn measure juice receive
    std::make_pair("17fbed35c4f760c1cdef0e5d9c0716c3e71ebbbe", 200 * COIN),
    std::make_pair("123600edee6510edc1ed52f109c40155d38b6b84", 200 * COIN),
    std::make_pair("8aab349cf0e25f57f9615fbee70430fd17c41e34", 200 * COIN),
    std::make_pair("f6e5f678591a0b48975d9cf79f0807e9b3053e4e", 200 * COIN),
    std::make_pair("ca0ccffb9aa8f91343742c9a05de94be44723826", 200 * COIN),
    std::make_pair("835bbe9f10a87e89f5ec8555b80de765b76ce44f", 200 * COIN),
    std::make_pair("88e9178afb3763acfe5c3019faeddd02784b5abb", 200 * COIN),
    std::make_pair("1eb1c9577935515c182b784dd30b8b5854db6fc5", 200 * COIN),
    std::make_pair("28e5ed66876a5565196bb4707d990248a155fafa", 200 * COIN),
    std::make_pair("cf96ef1a48089b1415c8af48af164669b176ba54", 200 * COIN),

    // hire scrap orange news frog movie layer view property judge unusual ripple female angry wire betray fancy below air viable shrug duty nest ugly
    std::make_pair("508f8061e3ceb6dca6b81f1ee06f4ff4ed0ba40d", 200 * COIN),
    std::make_pair("8d717cd36f6263ed1ea658cadc4bfe4df23b174c", 200 * COIN),
    std::make_pair("80721b20eca7304e3218dc26898337cc366d562f", 200 * COIN),
    std::make_pair("10ef2fab82816839be54d3bfd4aaa2b5e5e08d04", 200 * COIN),
    std::make_pair("265a805b45cd7191d3f5e7cd0b3bf7a123c90a0c", 200 * COIN),
    std::make_pair("7fa8e1bfcb6eec1fe0859cd6890454a59e028af7", 200 * COIN),
    std::make_pair("4d114a192ce0204df7d8f7b03534ef8e582dc910", 200 * COIN),
    std::make_pair("a9bb3a6e55bb74aee39630e67c7bb0ec371211cf", 200 * COIN),
    std::make_pair("62d55dc981e71c172a91c7bd3a6928d3dd4b6e01", 200 * COIN),
    std::make_pair("7e8e4b39e24452a9b3e3a049a1509ab6fdddd5da", 200 * COIN),

    // seed culture submit seek ask slab stove zebra family vibrant skill hundred royal off volcano owner boost globe warfare history measure unaware borrow puzzle
    std::make_pair("131b84da0f5124daf4da55442ba5118e967dda4e", 200 * COIN),
    std::make_pair("078a75eda6cb176b259d2b9242aefe74f2e60e19", 200 * COIN),
    std::make_pair("499a3562874996d622255f64b1367442a7706518", 200 * COIN),
    std::make_pair("08b480115ad97f7388cccdd864d7030b7ce70b18", 200 * COIN),
    std::make_pair("4c5e234c44290e50362a3e0ea199a0e522650d3f", 200 * COIN),
    std::make_pair("bb1de0f94d396e7d09d997b77e402142f4af6266", 200 * COIN),
    std::make_pair("b7a823720b01a96e95f13e62a6d59cfb46f4a641", 200 * COIN),
    std::make_pair("3a9da2705bb5eb2e7be1923a972454e189e3cdf6", 200 * COIN),
    std::make_pair("f98d158cc97e9a20fdf023ac662ac621d1d71d5b", 200 * COIN),
    std::make_pair("ebac9fe7bea2532deaeb8079d672239080f84f4d", 200 * COIN),

    // display either come bitter reopen bachelor beauty trumpet clip arrest hole review guide decade depth top novel execute shell nature fence submit connect stand
    std::make_pair("be368788cd3087e10b86ff51dfc1f974d01c032d", 200 * COIN),
    std::make_pair("163e692b871269fc294b269de8f07c0c20282ef4", 200 * COIN),
    std::make_pair("d7d6a445b2d6d6fb557aaafe8edc1e13a15fdfa4", 200 * COIN),
    std::make_pair("97186eb49bb9ef25a3f51ff521261884b47e8590", 200 * COIN),
    std::make_pair("5c0cc6180781f4f0e565a309112a7412351acf2a", 200 * COIN),
    std::make_pair("7b14a17c57ebf16cfb3cf3fd3d88811b7da4a801", 200 * COIN),
    std::make_pair("a526b63fae7888651b0c08086b56de6d9d618c76", 200 * COIN),
    std::make_pair("4f133401c34a0d6903d6c8a86b883cdd72e15c9f", 200 * COIN),
    std::make_pair("3cb49c27d5e40acab50b954c119e48da289ae565", 200 * COIN),
    std::make_pair("411b8bd79454cd8b7a3ccd4f741ba6d87a71b1d4", 200 * COIN),

    // cage surprise define civil orchard fine market deposit weapon border treat offer spy apart drum punch toward lunch banner south lion lizard remind valley
    std::make_pair("dc250a07af1f331a6f5046631f47d9e66f2295b6", 200 * COIN),
    std::make_pair("be6e465fd41fb040c5ad43b026dc8935f1156c49", 200 * COIN),
    std::make_pair("373fed5629a54d0428257ed87214726e61fb7136", 200 * COIN),
    std::make_pair("b1490fa1d9596b6b260e74a1f0ca880ddc4d3bb9", 200 * COIN),
    std::make_pair("33fe186ba9ac97b53e2639e780affa7453545d8a", 200 * COIN),
    std::make_pair("8879e2de6436c3f36d26d17dbbc62b37e9a579be", 200 * COIN),
    std::make_pair("2883cdf7b7bbb0a3a1de79073cf37363bb294e1e", 200 * COIN),
    std::make_pair("ede3dfff20bd990a32a68b0fcea5f9f88528bec2", 200 * COIN),
    std::make_pair("9e224a3945b74f4adc2c8d3b40a8d202d308a926", 200 * COIN),
    std::make_pair("b76af165f6fe883be2e1f3989430e0ccc7cb1f0a", 200 * COIN),

    // spatial wasp equal shrug boss humble almost neither rely village ignore refuse fitness boost gather furnace scale fade build snack ribbon you fantasy ensure
    std::make_pair("e7624b1bd3da20c26143587152645e3967f904b9", 200 * COIN),
    std::make_pair("cc4b480904eaabd0f9d116503e72c737b2bf13cf", 200 * COIN),
    std::make_pair("de4575dc6d12e700ccdb5d6df539d13fd6276466", 200 * COIN),
    std::make_pair("652a2d0c9f76e57f825dbc985911f7941f54390d", 200 * COIN),
    std::make_pair("a274b92b132ffa1d968b7f24a85297cd5ba75ab8", 200 * COIN),
    std::make_pair("125e2a653376bbd65fd7fb8de4bae307d748f39d", 200 * COIN),
    std::make_pair("56beb0a1950ef1c47c27e787fe3f8740c4648943", 200 * COIN),
    std::make_pair("34ae567cc1e805f80eb39d572e16047c3b5eb18b", 200 * COIN),
    std::make_pair("5faa179cca8bbb30120e5cf547ecff3d198971e2", 200 * COIN),
    std::make_pair("92da58a7344685c2881885176d17d0c54545f5ba", 200 * COIN),

    // asthma spot scene delay oval mansion apple narrow hour swing pet despair job fancy toilet race penalty athlete gap patrol impose olympic vendor alpha
    std::make_pair("b2c04cc484c5c2ed1f54009123487f7c19f4191f", 200 * COIN),
    std::make_pair("fba64e21f5c3311a969e4390e209ec90b795697a", 200 * COIN),
    std::make_pair("f91bf09d0532d472de612f860f2f837737d69ca8", 200 * COIN),
    std::make_pair("6a915560e4ca0fb02295ccbe2811f05abde9ce29", 200 * COIN),
    std::make_pair("ef771543360266b3dade823d6b503119d0dd10e4", 200 * COIN),
    std::make_pair("935b732bdfd61f6e9cb108431be5562d31b17d8a", 200 * COIN),
    std::make_pair("9f438a2d5b9fcda4546761b891c4eb7906119ce3", 200 * COIN),
    std::make_pair("f5103c0192ccd1d5ad043f0d65b1417d13c9d3f3", 200 * COIN),
    std::make_pair("bc86188ccfc50482216093aa4968b63bd522dbb6", 200 * COIN),
    std::make_pair("1525fec348857439ae6bcfa3165b2d11be830ab4", 200 * COIN)
};
const size_t nGenesisOutputs = sizeof(genesisOutputs) / sizeof(genesisOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputsTestnet[] = {
    // TODO: Define official initial coin supply.
    // attend promote either addict soup angle powder draft subject lawsuit return vague athlete cover settle solve ceiling rabbit opinion multiply reopen inquiry giraffe melt
    std::make_pair("254fa4c1cf5767dac464c07677cb1f06eb458414", 70217084118),

    // stamp teach ostrich rent rail palace sudden afraid sleep stone spike drum breeze six record brown skirt stadium reform height creek meadow cross wear
    std::make_pair("9c627fe4ca2170fb3e5e3b692b554f2ec75011ab", 221897417980)
};
const size_t nGenesisOutputsTestnet = sizeof(genesisOutputsTestnet) / sizeof(genesisOutputsTestnet[0]);


static CBlock CreateGenesisBlockRegTest(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

    CMutableTransaction txNew;
    txNew.nVersion = PARTICL_TXN_VERSION;
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
    genesis.nVersion = PARTICL_BLOCK_VERSION;
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
    txNew.nVersion = PARTICL_TXN_VERSION;
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
    genesis.nVersion = PARTICL_BLOCK_VERSION;
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
    txNew.nVersion = PARTICL_TXN_VERSION;
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
    genesis.nVersion = PARTICL_BLOCK_VERSION;
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


        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

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

        // By default assume that the signatures in ancestors of this block are valid.
        //consensus.defaultAssumeValid = uint256S("0x0000000000000000030abc968e1bd635736e880b946085c93152969b9a81a6e2"); //447235

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
        nBIP44ID = 0x80000090; // 144'

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 225;   // 225 * 2 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        // No need to import coinbase transactions.
        // AddImportHashesMain(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 100000;

        // Create MainNet genesis block
        genesis = CreateGenesisBlockMainNet(1523355070, 89249, 0x1f00ffff); // 2017-07-17 13:00:00
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0000d4eca6bf61e681d9656fcc32b14b4dbb9eca97cca9fb4b1e0b6bd7c01cf5"));
        assert(genesis.hashMerkleRoot == uint256S("0x5209723d5612a46836b3ad1f4ccddd254e24b80cbfb72e002b939a6b33798ded"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x6469c0da68980d85d0972eb8d2d74480630025ffcf8d43a9cbb9a7fc16bf4b14"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        /*
        TODO: Add eFin DNS seeds here for *mainnet*. i.e.:
              vSeeds.emplace_back("hostname");
        */

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

        // By default assume that the signatures in ancestors of this block are valid.
        //consensus.defaultAssumeValid = uint256S("0x000000000871ee6842d3648317ccc8a435eb8cc3c2429aee94faff9ba26b05a0"); //1043841

        consensus.nMinRCTOutputDepth = 12;

        pchMessageStart[0] = 0x08;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x05;
        pchMessageStart[3] = 0x0b;
        nDefaultPort = 40827;
        nBIP44ID = 0x80000001;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 225;   // 225 * 2 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        // No need to import coinbase transactions.
        // AddImportHashesTest(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlockTestNet(1523355070, 140933, 0x1f00ffff);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00007e065799d78ca1694671e6395ac84300d1cbca127525c4b121c3cb9f51f6"));
        assert(genesis.hashMerkleRoot == uint256S("0xf6991e864b07abe0e251c69fae1e90e8625d4bd9893bd3decdad743775792bd2"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0xea975b4897195287867eb8922c2ae20b6f469692cd098e1d3b16a86112046d3a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        /*
        TODO: Add eFin DNS seeds here for *testnet*. i.e.:
              vSeeds.emplace_back("hostname");
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

void ResetParams(std::string sNetworkId, bool fParticlModeIn)
{
    // Hack to pass old unit tests
    globalChainParams = CreateChainParams(sNetworkId);
    if (!fParticlModeIn)
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

