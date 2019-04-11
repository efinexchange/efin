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
// movie story spare nation lamp lemon supply gospel unable student false seat load strong air about decide truck select tube mobile fancy vessel play
std::make_pair("87608214c1618fb3c2bcdd1456fd28bac102a825", 3593750 * COIN),
std::make_pair("270ce9398c35895212522611991869d477d51ace", 3593750 * COIN),
std::make_pair("dec50520e581eb0eadd872956a9dce25df1604aa", 3593750 * COIN),
std::make_pair("afeeee4ab3dc6167d1a86f6e98b9ccc749432468", 3593750 * COIN),
std::make_pair("760ff2000b2fe919cae4374bf1e64691b1e25d5f", 3593750 * COIN),
std::make_pair("99811d6b2ebb77998bb055fc7c746c518fbd43c6", 3593750 * COIN),
std::make_pair("c2c048c7b138cedbafb0cd67cb076ed51bbda31e", 3593750 * COIN),
std::make_pair("6dbbeee65afa5d2fa8dc97d83bd83bcd41d9d09c", 3593750 * COIN),
std::make_pair("9a14adfa351b8a883ccb36d5e27165ba133e72e2", 3593750 * COIN),
std::make_pair("1ac764520c965937e9ed10de683520ed73131268", 3593750 * COIN),
std::make_pair("0ff088f9009840b773895622699c9920c9f634ac", 3593750 * COIN),
std::make_pair("2000457bff2da7597b8d3a76d6e38e3c1985a2c5", 3593750 * COIN),
std::make_pair("2dad652a163aeee3edca31f937cf23b29f27eb75", 3593750 * COIN),
std::make_pair("66adbedc1e0f06bf2f11472fae2c43017a27a358", 3593750 * COIN),
std::make_pair("9ac6fd51860f6a50a07f4a211dc4193ee442fdaa", 3593750 * COIN),
std::make_pair("fb563a367746aa0f5c267b49c54e7e7e8cbb9fef", 3593750 * COIN),

// relief swim enrich leisure thunder away palace skill light gesture valid buffalo stool sell warm enlist laundry harbor food mansion circle mom swarm goat
std::make_pair("c89897f1c3f1849c6750ee40010150a5b6e5981a", 3593750 * COIN),
std::make_pair("e5b422461ce1f3216668e00e9d59e80d111387f1", 3593750 * COIN),
std::make_pair("a3c9fb250d302f43eb066c560215e7de00997ed3", 3593750 * COIN),
std::make_pair("d29dbe27e4288c0da3bf089148570034733321f9", 3593750 * COIN),
std::make_pair("ead6875f560f8a39aee8a826a6de855b508269fe", 3593750 * COIN),
std::make_pair("af63b486890ecc3f43fbb644ecf73e8df75f81d0", 3593750 * COIN),
std::make_pair("bf3066ddf6dec2b85e13326e9fb69befc3f3eedc", 3593750 * COIN),
std::make_pair("f93003f7b19eb2b607b5429c8bb877ea7b91f7fa", 3593750 * COIN),
std::make_pair("9bb34cc12448ea6933e2f4c9b9a8fa6a5497de7b", 3593750 * COIN),
std::make_pair("0746c3341bfdc26161e3f43cfedf1c8287938780", 3593750 * COIN),
std::make_pair("c687a7f889c3a0ebbd4e23fb94e14fff5cc3e562", 3593750 * COIN),
std::make_pair("eb38fa4ae01b465822175122162c0f4d61cc8912", 3593750 * COIN),
std::make_pair("8d48f51645f8f4b6f1fc6722008a617d943a419d", 3593750 * COIN),
std::make_pair("6bf519c188a93cc18c26f6b9b566ff9f1efdf693", 3593750 * COIN),
std::make_pair("8839bb82bfb0d76592bb30d815cabb630bd682ef", 3593750 * COIN),
std::make_pair("ebcc6547a7eb8afd1f7121125638f2cafece5bd5", 3593750 * COIN),

// obscure team grid cave police couple spider flee art skull cancel fade abuse energy seed pink there valid cat detail plug police slogan belt
std::make_pair("a3e90e9cd8870268dfc94802e1caa29d2bde0ffd", 3593750 * COIN),
std::make_pair("7eda98268cc6a2db44abb6b4cbc92d3b1f2b753f", 3593750 * COIN),
std::make_pair("89cb2c411a57d215eed64353a236000882c9ab46", 3593750 * COIN),
std::make_pair("016b2d5919873bf0b8979f9b51aba02e6f131271", 3593750 * COIN),
std::make_pair("fc6ed89de228b6ef3a3f61578a0309804d33a6f1", 3593750 * COIN),
std::make_pair("8391776721923e7c8f03dcb77a49659906bafa09", 3593750 * COIN),
std::make_pair("af06de323525af76b86f9977b6666170738e74a4", 3593750 * COIN),
std::make_pair("0932d8d0e1709d562e52d39c74a9d29203a929a3", 3593750 * COIN),
std::make_pair("0ef5bf48fcc9e3392425c1eb80d12930e8a44378", 3593750 * COIN),
std::make_pair("b3fb971ea274316d44d2dcd5585a265575e7eade", 3593750 * COIN),
std::make_pair("c999c324c25e446e1da8e89368242b4cddc8803f", 3593750 * COIN),
std::make_pair("6e3e127f2314f5b3d7df97cf6e662376ea4298c3", 3593750 * COIN),
std::make_pair("dc25f4ff5804f4f4114e9f9c07168cb05dd1e978", 3593750 * COIN),
std::make_pair("6cecba3081feea0a2c9afa498ebaa965945e7445", 3593750 * COIN),
std::make_pair("109e2a89a0db54a0655ef94fc9d461bb345e129d", 3593750 * COIN),
std::make_pair("b6aef6c20a9762555603e82a4e5d05fd2d766c8f", 3593750 * COIN),

// topic autumn sustain weather whip opera pair quote slender clarify bulk shed cupboard off anxiety winter bamboo short clever title rough dinner devote library
std::make_pair("f51e32cdacec377dd5b8a5c156c97c48b5000a16", 3593750 * COIN),
std::make_pair("078688959b3d845a8313b9dfff037bc3e7591611", 3593750 * COIN),
std::make_pair("0cd3e6d4921310302566e691701c82e0a2963dc2", 3593750 * COIN),
std::make_pair("5093cd3ec003f1e065e2de4ee5548c1ee135b654", 3593750 * COIN),
std::make_pair("82b7f59f5399a9f76511fb38891c67881b95fd76", 3593750 * COIN),
std::make_pair("22c8ad84256494e4d1264ace05a31222c53411f5", 3593750 * COIN),
std::make_pair("e6f12fd90c572aa88edd7aeb6318aa20cac83064", 3593750 * COIN),
std::make_pair("0c521724caa6ea837288d94758a9ef8d3d960558", 3593750 * COIN),
std::make_pair("a93697bfb04a377f79d783f296a357a1fa92c5b9", 3593750 * COIN),
std::make_pair("1b33a33b7f00ddba54d913debbe31392f2f10170", 3593750 * COIN),
std::make_pair("9ccbdb82efcef6946a4f2f01cb382e8d4fb15c2b", 3593750 * COIN),
std::make_pair("d3a052d732d426f6d6eba709ff2c3bbeba1e1c66", 3593750 * COIN),
std::make_pair("76831b5ed41b314935b57439609d569d4a6e2e1e", 3593750 * COIN),
std::make_pair("ba02a7f3c8a0af0af2105a618a364aa0bc8d0198", 3593750 * COIN),
std::make_pair("9c14587e43296ae49a3aa8989098e64ed5ad496d", 3593750 * COIN),
std::make_pair("aabba630c78b121b03bd9d5d6cf46442a554fb04", 3593750 * COIN),

// pond slush blanket search suffer poet author rate bone menu deny bracket wedding vast horn devote ginger maple purchase hidden raw junk goose crack
std::make_pair("f76dc922c0c1cd67b43b82dfa1460a150192646a", 3593750 * COIN),
std::make_pair("fae5cb95d4ffe32f5ffa13f6ade032ba90539820", 3593750 * COIN),
std::make_pair("f3d300ca2023b1823e96a25a44591af92a887c04", 3593750 * COIN),
std::make_pair("339f9698607efd53f9236e20dc1779e9032d9659", 3593750 * COIN),
std::make_pair("4e4cf677629535b0c3fcbb25452d74423f5dcc23", 3593750 * COIN),
std::make_pair("03c78e7a181020e003e63b791bc90c79397e3c9e", 3593750 * COIN),
std::make_pair("1534a61aabcdc7cfb3ac968763fca0b72c8921c3", 3593750 * COIN),
std::make_pair("fb7fbfdf08e731673fe4cec3a971f3a12629730c", 3593750 * COIN),
std::make_pair("d4c0796df0fef61c103422148fef0b1661d4a548", 3593750 * COIN),
std::make_pair("8938165876f65b581235d16b4495b256a3ed2d56", 3593750 * COIN),
std::make_pair("0773bc652e9dd74f32a517fd9ef452377fab3ef2", 3593750 * COIN),
std::make_pair("0053df1f9240df99f9a5c8fe824256310ec03971", 3593750 * COIN),
std::make_pair("bf7448616f28e5a233a7d11150d1faf22d8ad430", 3593750 * COIN),
std::make_pair("19bcc7a1afac6536f58386f279b9af285ee483b2", 3593750 * COIN),
std::make_pair("7db06d3b29479d0d24e8b128e2b7b8da1880e581", 3593750 * COIN),
std::make_pair("412d4e41fa34e8fe991bc861ab86ae6a4605c719", 3593750 * COIN),

// float faint private border cheese bleak fine dismiss slogan bunker wash seven morning wave defense absent corn excess raise check myself improve hen eager
std::make_pair("74bbfad1e8ae8dce1e69bc69f69bfe7fdefcd342", 3593750 * COIN),
std::make_pair("dcb5d7b5e6266cfb0e9736557a7f40ce1b949c80", 3593750 * COIN),
std::make_pair("5dd998fe199335fbe90c913431e3a931732c8161", 3593750 * COIN),
std::make_pair("05c4ec3cb83d6c2e7b90a1fa62a75cb7deffb8a6", 3593750 * COIN),
std::make_pair("7e276d1a117e25af85041d5d7282fc1c61539ffd", 3593750 * COIN),
std::make_pair("a66f3382e0690fea1f193397a8f9cd83824ad74f", 3593750 * COIN),
std::make_pair("b69efb0d8f2f8fc024add9b142c4132d1931cb68", 3593750 * COIN),
std::make_pair("3cf7eb9a9fbcc54368bdaea23a720412af02570d", 3593750 * COIN),
std::make_pair("b37fcb7510383acfb0e7ca7b37f06ea6b1ecbdf5", 3593750 * COIN),
std::make_pair("7d57b347f70f370449f10d25ef0bb0caf3a9c23a", 3593750 * COIN),
std::make_pair("369e03b66cc5c22b914aad04b46391a1653cb7a8", 3593750 * COIN),
std::make_pair("ee247662798680fc6912b6dbfc08c5641ab841b4", 3593750 * COIN),
std::make_pair("48dfe2ae61460d73dc2ca0eae3b3177bef649cc9", 3593750 * COIN),
std::make_pair("a04f81238dea6a599bbccb480feed4f1187194d7", 3593750 * COIN),
std::make_pair("411527ff55047bb4c928294662332bd871b26575", 3593750 * COIN),
std::make_pair("64a6b5eed2df268db6a810d2b0ba4ec1ce2e8962", 3593750 * COIN),

// bulb rocket system digital helmet nerve isolate segment thing park clump before seven good concert steel august romance garment laundry drop plunge paddle warrior
std::make_pair("67930f6606d029c9b4a5269d121ad7ec5f4efaa1", 3593750 * COIN),
std::make_pair("4beae929eef2c3e5291d2b2bb8ca36a8ab2eac38", 3593750 * COIN),
std::make_pair("b82f520abec580a5efb5a13d85760b2d89b5f520", 3593750 * COIN),
std::make_pair("3eaf1fd8586328d40a4af386b21f314d5f5bfe42", 3593750 * COIN),
std::make_pair("8eb241cc35863a32ec4f2170b9662142306b78ff", 3593750 * COIN),
std::make_pair("50a2e04ee59355651ccc63a0233b854691644a9f", 3593750 * COIN),
std::make_pair("b6a39a4a31a25086a77cc58afe9e7b4662b8e8e6", 3593750 * COIN),
std::make_pair("3a748b9374686cc50e4380cb169e4528fff0bb90", 3593750 * COIN),
std::make_pair("a646e764d5390981742fef96d593c7b6dbff6163", 3593750 * COIN),
std::make_pair("ce71b67d51656d33b8a12ed54c0db379cd247ec6", 3593750 * COIN),
std::make_pair("c6cf3d0807c9aed23d74eec4b2f9a0a40768ca25", 3593750 * COIN),
std::make_pair("e37c3163ee1201ce76ddb7a6dc4de8868a52eb19", 3593750 * COIN),
std::make_pair("f5a8d4291701a94dbaea594ee6bdaf5ced845360", 3593750 * COIN),
std::make_pair("cd6f48b6d53705b0ff919bee6dc7c153239a732b", 3593750 * COIN),
std::make_pair("c26fe9552bac43f11038f2c181e2b3851283a79d", 3593750 * COIN),
std::make_pair("c1def0b1fb479d76b5337c8255a6dd49f9d45653", 3593750 * COIN),

// maid reject joy type city flat before bring broom carbon miracle critic vote mushroom gadget nasty label milk effort trim slam program survey exile
std::make_pair("09aaf56e5b84af7b65f7cb2d1742f473ea6c8dd2", 3593750 * COIN),
std::make_pair("4bdfb428c67b9c1d2668378dfe0d3b2f0723bd2f", 3593750 * COIN),
std::make_pair("53bdb246fc6c9852459cddf328c06fdad44d01f9", 3593750 * COIN),
std::make_pair("b2b62a1ccf60a0f992fca0269c4f6b084e2fa868", 3593750 * COIN),
std::make_pair("e8043da02dca23f4b86c208975752450d8f452ff", 3593750 * COIN),
std::make_pair("d3e6434e73dacdd058c506f2bd771b51c408082c", 3593750 * COIN),
std::make_pair("ef5f550a256a7e569562cb0485ab33003d9f4d90", 3593750 * COIN),
std::make_pair("80be9d22fe9d4d988d93e967c516d9bcceb16915", 3593750 * COIN),
std::make_pair("6b830d36e1909ecf83775171c5200370cd3aef7e", 3593750 * COIN),
std::make_pair("6dd69a4f345f1f28e8e970fc83cff27f819370fb", 3593750 * COIN),
std::make_pair("b741c4743d6dd37ffe94aee235cbd67378669e26", 3593750 * COIN),
std::make_pair("2ea6934b3d7420c6bc27b749245d775033c27ea2", 3593750 * COIN),
std::make_pair("9dd8400ba34b889e6438c2bc3a272c24bce48918", 3593750 * COIN),
std::make_pair("6a328c5d3b891f4aaba3d14ed511eb0dcdf5f3cc", 3593750 * COIN),
std::make_pair("a98762886625d03914c53fb122871e527b50817d", 3593750 * COIN),
std::make_pair("1eb4f63c72413e4eead6dc3dea6ee3db1e590b89", 3593750 * COIN),

// axis excess advice buddy power arm sunset jewel over story estate apple verify battle electric match trade glad grow lake hill leg foil story
std::make_pair("5a2adfdaa0c3ac2dfd9b203081ed3174bff48221", 3593750 * COIN),
std::make_pair("9df51a2ffdf6317f50efd5cb20c2a4235897a180", 3593750 * COIN),
std::make_pair("2dcbf2e62be0ac8942f8f767b25683e72683cfc9", 3593750 * COIN),
std::make_pair("dc010a2e910f860ce2ec07ed61b3cf4c19a2f2b2", 3593750 * COIN),
std::make_pair("82d5cf935246a6eb97864f2bf26fbbdb907eaa03", 3593750 * COIN),
std::make_pair("c801b7fb81458dabfb588c2e27c019540affccc5", 3593750 * COIN),
std::make_pair("597fcc64eec308b17d54020e8d09ac56ddb35e00", 3593750 * COIN),
std::make_pair("c0a653cbf3b4e8715f3b242bcefef50efe2fddec", 3593750 * COIN),
std::make_pair("3b98a7b1f82dcef8fcfc9a9878aa68e1dd7df5ce", 3593750 * COIN),
std::make_pair("7da3f46c1fa08432a35bba0f9755ef9269ebe073", 3593750 * COIN),
std::make_pair("453ef20bd0b5c8600be8d3ce50718e293e8046ef", 3593750 * COIN),
std::make_pair("330a6ac196178d8854ba4fbde13be81d5f1b40a5", 3593750 * COIN),
std::make_pair("12d6350f7ac3afc8a5f8410783fb31a6c2fcfeac", 3593750 * COIN),
std::make_pair("1678b0db64fdf11439f647e19b05716eb37cd6bc", 3593750 * COIN),
std::make_pair("8b7614ea8e149be37ea26f3a7354eaf6a5b43126", 3593750 * COIN),
std::make_pair("88677d2df1818d4fe73b9f8242f74daca42f6336", 3593750 * COIN),

// sun vague father inject river trophy olive actress whale genuine electric purpose boss hole core simple nephew topple unusual bless depart salad lawn pact
std::make_pair("b7eb328326ce0bb98a83f1124feaa106247b429a", 3593750 * COIN),
std::make_pair("65f9ecc40ae5cdf376d92d0f5b6ba5e78ef4d832", 3593750 * COIN),
std::make_pair("39888963e8c05e1054cc6d009f1057772a458bb2", 3593750 * COIN),
std::make_pair("09aff8a3b5d2dc459aadd525aba7beeb5973e009", 3593750 * COIN),
std::make_pair("68d2f0f723a5a454b64438cdaaf4b56efdb782d1", 3593750 * COIN),
std::make_pair("261447aed16a62e79c6e31710f57f1216eb68db8", 3593750 * COIN),
std::make_pair("257c2f92b5d529a13d624ce8284eb470c5466a87", 3593750 * COIN),
std::make_pair("725224ac8af3ee63ddeefba8008cd907112252f2", 3593750 * COIN),
std::make_pair("d786be8325f10acb44e47dd8c2e43a04b859a7c8", 3593750 * COIN),
std::make_pair("65df949b85362850a2549f02b224d9af15c55215", 3593750 * COIN),
std::make_pair("3eb334dab25da01dc5da0c3d7d8bc8c0fe320473", 3593750 * COIN),
std::make_pair("19cede864fdc4a2ea2ea130cee2c41ce702dc657", 3593750 * COIN),
std::make_pair("d5f6d112ce4e4b2fa84e3c39bad77461669b1313", 3593750 * COIN),
std::make_pair("74dfbb50d8c80c7e9a2ef81288d4474de6b42a89", 3593750 * COIN),
std::make_pair("e16411e52ebae6025ad7b2c8f878088afc6827bf", 3593750 * COIN),
std::make_pair("4a85c739ab10de80ccbf6663c41cd64c297aaff0", 3593750 * COIN),

// yard brisk nut table cube image remember bundle demise ice need stable rate scissors around cloth inmate much hotel segment mask method tissue must
std::make_pair("0edc73e2bd0849f2557e35ecd58182c4fe03c35c", 3593750 * COIN),
std::make_pair("5a40a3217b0bf0e9c5e65ecaf00b665ca2f5bbf1", 3593750 * COIN),
std::make_pair("8b07d43a43d328208de2793b09624e347c08eadc", 3593750 * COIN),
std::make_pair("2e138a56321372f4178895e5d730034f4393a42c", 3593750 * COIN),
std::make_pair("af051fda7fe6722b2d09252fa8383c1c4e692d69", 3593750 * COIN),
std::make_pair("09ed98493f6c4ed9a62e0e4f1a5309b403097001", 3593750 * COIN),
std::make_pair("3ad71b3455ffa79f16669092c46e49b370a96cf4", 3593750 * COIN),
std::make_pair("4d8ff31687e02cd2d03f80e345813ad31473217a", 3593750 * COIN),
std::make_pair("a4d2f14a1c2b588e6f8258c00279eae82747666b", 3593750 * COIN),
std::make_pair("98853c21af539fb582a53dad3afde2bd2882b083", 3593750 * COIN),
std::make_pair("242559e172a1ebc71cde2a67346a8b1aba654978", 3593750 * COIN),
std::make_pair("c5e29f02078b58be31c02e9ee7baa2408781b255", 3593750 * COIN),
std::make_pair("dd2fe0f793a5fb1f3a24ca695558aad6d512bd7b", 3593750 * COIN),
std::make_pair("c6e1cde599f377314245bd57a92136e767f401b9", 3593750 * COIN),
std::make_pair("1a185f3f56aa09baf684acb2704905d0c3fd1004", 3593750 * COIN),
std::make_pair("ee93618e94088614d7caedb70f7add65255e0f77", 3593750 * COIN),

// stumble group cry spend nation random fuel sweet cable erupt sign canyon pluck dutch scene clerk holiday circle hold attend remove loan cable weather
std::make_pair("31cd6f19b75039c5365567bfa8119f76dfde9ea0", 3593750 * COIN),
std::make_pair("cff5eba6878cf446388c8af82a6c9e408d980758", 3593750 * COIN),
std::make_pair("68d9251226dd5d72722b45e65c96c3779a0db86d", 3593750 * COIN),
std::make_pair("295cbf33ecd208de8ecdd0d457040a92a5b2bfb4", 3593750 * COIN),
std::make_pair("8f79236a4fcc01b16fd90c0d16c683bb841c89a5", 3593750 * COIN),
std::make_pair("7014fadc41b05b354f442b1acf401c5fbbc2df16", 3593750 * COIN),
std::make_pair("e0e4c4622b1a6ce85144c0784a1c0b587f4febc5", 3593750 * COIN),
std::make_pair("c2b664a8c8e7109a676226969a1d9b5edeb019b9", 3593750 * COIN),
std::make_pair("4c10184fb938ab55a1c04bcd117ba70f36b17989", 3593750 * COIN),
std::make_pair("ce7812dbb1bcec1d8e5f8efa646decb70d29075c", 3593750 * COIN),
std::make_pair("b801f78b55ebb1138614fa9b81a8c100790615e4", 3593750 * COIN),
std::make_pair("10aa6760d23a305b9262c36ee8afe8ac6ea69e27", 3593750 * COIN),
std::make_pair("21cefc99be33aff36bdd9ba4d3c5a8df1f0929b8", 3593750 * COIN),
std::make_pair("9dfed9710ae28c8e2a8d096b66430e53e0175c86", 3593750 * COIN),
std::make_pair("6e0da8a02c4e96471534f844a412f2d67a4d0137", 3593750 * COIN),
std::make_pair("881f9d3ada45066098f61eff9c0792e96e1d92cd", 3593750 * COIN),

// nasty anger noble maze rich soup own arrange dice spoil head match swap comic bus curtain neglect spring youth gentle figure laptop lucky balcony
std::make_pair("e5a03611845e4cdfef08b1e42fdd9c0950843360", 3593750 * COIN),
std::make_pair("4e0c9cb12f83235e7ed75a05247f1f8d4e0367e0", 3593750 * COIN),
std::make_pair("81e464a13100abdfb9c820c7ef06515834ec3118", 3593750 * COIN),
std::make_pair("45b591d7fe8bd2716f31da68062a08dbc58407ca", 3593750 * COIN),
std::make_pair("b55930fd5caebe151f029c20b0d9dbd4028f07fa", 3593750 * COIN),
std::make_pair("ffb90be149bff199e75935ef82e3ce203dae3db2", 3593750 * COIN),
std::make_pair("f74cb2a84b9a84697f6bcc550ecadd47984908eb", 3593750 * COIN),
std::make_pair("157c707db9e010b897000387e0c21c9587d050ba", 3593750 * COIN),
std::make_pair("343d966e2125f890241d5e7d8d6b3303af70751a", 3593750 * COIN),
std::make_pair("301a9eb5919626c794209b2f47ff487e1bb597ce", 3593750 * COIN),
std::make_pair("beb76a40254a0544a5445f7d00e2b96303076f13", 3593750 * COIN),
std::make_pair("76faa4b713469f31222a11fa96a67e6434cbc458", 3593750 * COIN),
std::make_pair("e165758ca18dbdfb0d77a58c027955672adb84ee", 3593750 * COIN),
std::make_pair("e2ff3397fed03f123d03e31f8117ab8537bc24a2", 3593750 * COIN),
std::make_pair("ad020bba43724e5accb3083559e7d055b2651693", 3593750 * COIN),
std::make_pair("ac6b7f3754acdd9fc91a6676537e65c83f35b8f1", 3593750 * COIN),

// lady label notable frozen stem trip fatigue choice choose reform device cancel movie chat novel series pledge symbol giggle invite oblige old wife disease
std::make_pair("eaccb34d097fc00ac5fb61293f71428ef3492829", 3593750 * COIN),
std::make_pair("b376e4ddbf3c63bf5514e109a55a8599b72da30e", 3593750 * COIN),
std::make_pair("b0f41be1134be54500f0f8f8fb7bd286874cd503", 3593750 * COIN),
std::make_pair("cfcf62d9f26a37e61595981887feaf79ad6bbf68", 3593750 * COIN),
std::make_pair("676ccbfacf9a7cfa45a61dd57553e131c9ceb182", 3593750 * COIN),
std::make_pair("63faf7c97f2d5cae4fcbc1343f73c0f443a8f8b0", 3593750 * COIN),
std::make_pair("ca12f592cdd6f8c88958e439801bcad513128f5a", 3593750 * COIN),
std::make_pair("d87d68ea9935a1656bd9b97e0f8b0bcbc86d09b1", 3593750 * COIN),
std::make_pair("cede74fbdd083b96be8fc04ac6a5015aff404460", 3593750 * COIN),
std::make_pair("4cf2f01100ff8f7ea1245b41813a7eee409243ee", 3593750 * COIN),
std::make_pair("b45af5b3726866e4fc2a4ecb1bfe3f90c715ec27", 3593750 * COIN),
std::make_pair("afb159112c0c2497358e9f17b9869c6c16c4f877", 3593750 * COIN),
std::make_pair("0aba26ce073c7dd9cd4907d9657f0320a4154604", 3593750 * COIN),
std::make_pair("500a412d54f345457f87064e85c10d7980cb8a18", 3593750 * COIN),
std::make_pair("0c1b2e1c51fef0332d0f00391db0922e1a159b65", 3593750 * COIN),
std::make_pair("f0641818672344f324e875ae4a485d371a194126", 3593750 * COIN),

// age hard unlock family path immense south choose addict demise priority cage width cricket flame obtain slogan recipe polar dress mosquito spider pottery remove
std::make_pair("43991f364facc2efbbe9290fcef2920c6bec7ab3", 3593750 * COIN),
std::make_pair("15728e3dc868900beb5399913d3dba19b40a61e7", 3593750 * COIN),
std::make_pair("e5db42d595f4102fd5eeca6abc9b9c70ac323c27", 3593750 * COIN),
std::make_pair("b11bc94f06b08691d833406f9d901ac6a17a2ccf", 3593750 * COIN),
std::make_pair("340d9dcd6c3cbab96986713a1401d66f07b3a61d", 3593750 * COIN),
std::make_pair("49fa548497f5b815a259f393065a4ed5fa6a1f01", 3593750 * COIN),
std::make_pair("bd5e690a5ed2fcc35213d090fd5b4b74c4f6d827", 3593750 * COIN),
std::make_pair("40723394bcc3c829ff17e2070e62300c028dd08d", 3593750 * COIN),
std::make_pair("155e4e56293c05028588c0d694b67d36a7c9ed53", 3593750 * COIN),
std::make_pair("2aa6ecd15d4af274ac34608314ffd963b1324ddb", 3593750 * COIN),
std::make_pair("12044aeb620d80be59d6d2a897ae0302d9c96885", 3593750 * COIN),
std::make_pair("982d5217b050e52b6960b57671065d6d0a0f29ee", 3593750 * COIN),
std::make_pair("ad30937c8771d06672b37cce1ae55c005639d68e", 3593750 * COIN),
std::make_pair("7f66ef9afa68a49b991e327fecc77ce43016fdba", 3593750 * COIN),
std::make_pair("3b1f2154bfd8d5b4186728a18e66a6ed7616b20d", 3593750 * COIN),
std::make_pair("dc039e6e196f040e56ca07fce478adbd17c41ccb", 3593750 * COIN),

// raven tissue innocent saddle shiver six clever goat apple alley method arena verb other galaxy winner sick they push maze surround page oxygen digital
std::make_pair("53b80acb5ad7f2795e1633c1550f9906beb0486b", 3593750 * COIN),
std::make_pair("6cc54cb4d1cafe4bf9a55385ec5d12e8991f95da", 3593750 * COIN),
std::make_pair("dfeb051a9fed31f87c06fe75315501fc3c49a777", 3593750 * COIN),
std::make_pair("b38c18447490d8c50da513ad6bfe7e5c7b993e8f", 3593750 * COIN),
std::make_pair("1e6acf1a2181d1ef376e1a1466a2512db373bbf8", 3593750 * COIN),
std::make_pair("eee75f380108d2d9696953532c46d4b39acf837a", 3593750 * COIN),
std::make_pair("91dc664f1491525625f7871f755d156ca4dcac14", 3593750 * COIN),
std::make_pair("f138a5b2fb1a012bd60e9eaa6ba8b45439b4ff23", 3593750 * COIN),
std::make_pair("cda5a96fd92e1224c38b4dc5ef216c81427fbec2", 3593750 * COIN),
std::make_pair("3a6e5437fcdb3b7d1d20aef4134fa959c1241e5a", 3593750 * COIN),
std::make_pair("b76746537f1833b4c3df71108ce21ea24233fa97", 3593750 * COIN),
std::make_pair("ca88951a7860ad0f202035d990810f58346ab035", 3593750 * COIN),
std::make_pair("70be8fdac6937183b2e1e0dd64bf18cdef989593", 3593750 * COIN),
std::make_pair("3739009963d26229c9317d70f1fb4b0dc0f87cbe", 3593750 * COIN),
std::make_pair("8c3f95d790a7944c0aa7cfcda80bf30eb3ee4a20", 3593750 * COIN),
std::make_pair("90e0980b7826d4c2a4c87e7317b29ea4c984e789", 3593750 * COIN),

// suit climb until valve toast mutual topic sock shrug finger lady rude express salt dentist birth meadow end crack wash pattern rapid horn artist
std::make_pair("00611cbb3fdbb6094fe3f5843cfa75559f0d1cbb", 3593750 * COIN),
std::make_pair("45d8e6ed6274dd0679016549a17e1f0522b22696", 3593750 * COIN),
std::make_pair("51a6ea2b9e7477afafff6cea5f71b8eeb1e641f2", 3593750 * COIN),
std::make_pair("71bc74ab3d2db491e08825db2594f92a92991746", 3593750 * COIN),
std::make_pair("5d9bf32c585b5c7739b66c22bf91841a8508a0bf", 3593750 * COIN),
std::make_pair("bf654e47704500f5e5c00dba883aa1837c1be6d4", 3593750 * COIN),
std::make_pair("3d673d426162ba323aecb97a0dabdfbd2094d5d0", 3593750 * COIN),
std::make_pair("3ad25ad37db3c82e6c73192ca50ae7447e1df341", 3593750 * COIN),
std::make_pair("d05c4932daa125949aa5034b1c3cab16bb9dcf23", 3593750 * COIN),
std::make_pair("8b2a154288078fdccbfe506038d297e9768052fa", 3593750 * COIN),
std::make_pair("befc97176438d040d4657db8b12e83708d678bbd", 3593750 * COIN),
std::make_pair("a169c0f23a0087ad61e8fd9083ffb87ceae6b593", 3593750 * COIN),
std::make_pair("f1bf58dcf54e3c1c8d29a79252a6abede744a1d3", 3593750 * COIN),
std::make_pair("3ed3a439fe7669a80f7906a2c9a3fb683c6124a9", 3593750 * COIN),
std::make_pair("546771376e058db67de856918e855aa04e9205aa", 3593750 * COIN),
std::make_pair("bc07f04baf454b07fe8650a2ec394131a566b354", 3593750 * COIN),

// wet era distance ritual tone size first bracket domain pony rude error diamond city blur mosquito outer brand pool enable account kid energy payment
std::make_pair("cfa49c17748cf2f48023809e41821a157471d157", 3593750 * COIN),
std::make_pair("0d3b8b0b50733a350952c17329550118a8d58478", 3593750 * COIN),
std::make_pair("c8ea56a7960833dd18842ae7b98aa9126a3ed26b", 3593750 * COIN),
std::make_pair("cd5e583d7b98f7e5a7a503dfc2fa897f2b5aafcc", 3593750 * COIN),
std::make_pair("8620dd0546774a55153cf3ebdedf393b02e5adab", 3593750 * COIN),
std::make_pair("c37cd3658ef010144fdd6da2605fec81189e75d6", 3593750 * COIN),
std::make_pair("1b6cba140dced26c798c71b31a09d612d8f1c22f", 3593750 * COIN),
std::make_pair("6ca72f905e5b9ca84490164ff5fa52afd9be8c51", 3593750 * COIN),
std::make_pair("0aad42ebaa50a3c9a29c1487e637500a009a8f18", 3593750 * COIN),
std::make_pair("da00221a8b6fd7748664e0285b6ccc4de05fb285", 3593750 * COIN),
std::make_pair("1904d886b5736b4ae385a6958c697b89958c353d", 3593750 * COIN),
std::make_pair("2cd262f5451fcc8fd869adc10758bce2805fe6ed", 3593750 * COIN),
std::make_pair("c81eb57d556627cb553eacb4e39a8019bdc48082", 3593750 * COIN),
std::make_pair("6c287e8772e91076805953f075d6a6d4b0aef665", 3593750 * COIN),
std::make_pair("a02c59863ce7cb9cbda078f7fe3ebfcea14663e3", 3593750 * COIN),
std::make_pair("f6d885a61faf14ac7415217b5b43ba809613749f", 3593750 * COIN),

// only shuffle equip detail dawn mushroom doll elder dry lava rhythm comfort agree liquid narrow drum famous melody rose bronze purity chaos core man
std::make_pair("9b08025cc4a3e74f742f9bb579b415e31b1048de", 3593750 * COIN),
std::make_pair("c980b90cd0064a213f8065b61977ba44edd3c0e4", 3593750 * COIN),
std::make_pair("9047fdb901d1ebf86ac3d75a274906a63d0a87e4", 3593750 * COIN),
std::make_pair("52fbe0ba8b9eaef9b680b80d76d440af70e970bc", 3593750 * COIN),
std::make_pair("b37688fe924abf7c9395c6c29d8657aeecb7a56d", 3593750 * COIN),
std::make_pair("8da265a5e00ac46ad303bd6de7544f8cd90447a2", 3593750 * COIN),
std::make_pair("87534459bcd77bfcf9bd2d32e39cd660b4a2bcc7", 3593750 * COIN),
std::make_pair("0e942553d394a45317dcbda6e23646e9c104528f", 3593750 * COIN),
std::make_pair("9817b940ab7eb4bdf21995f0dbf4343193314584", 3593750 * COIN),
std::make_pair("04ee854d67d2a58f0a041c7d09ac259accd54f8e", 3593750 * COIN),
std::make_pair("5c4c7d8bd3dfbd691c442987ad7f9f2ab45c3fdb", 3593750 * COIN),
std::make_pair("13b8f85e7ab1e88046aea1d288de44dd8c0ced7e", 3593750 * COIN),
std::make_pair("74571b19d637127fc482d98a9bd5bc6f215651a0", 3593750 * COIN),
std::make_pair("9f06977d0e834eaa0e5c2e54c8e28b37f5ece6d6", 3593750 * COIN),
std::make_pair("a731f52e506efa7c8d6e30018d2fb1ef349012fb", 3593750 * COIN),
std::make_pair("79ef9cff7f7d2e090dd99fbc37058f89b20aadf3", 3593750 * COIN),

// rather mosquito spell myth make leg anxiety apart oblige else jaguar mechanic board hungry wash census sausage guard open trick wing illness wreck image
std::make_pair("4b8d6aaf9d94a56f46ed57df36257047a97dda7c", 3593750 * COIN),
std::make_pair("fc8f58cfaedc235413cd8400e6cf6c064f15c86e", 3593750 * COIN),
std::make_pair("51f867dafaf5182674669c0f5db27a137f313b4e", 3593750 * COIN),
std::make_pair("61187ae3a836d9dc5ab8ee743d711d0087444d79", 3593750 * COIN),
std::make_pair("d71224e08cd7affb043ae2310467ce3c0f453f33", 3593750 * COIN),
std::make_pair("a22dfc171ac446a460da5ba8994e1526045d130d", 3593750 * COIN),
std::make_pair("f9af78bfd720c7b0f835c046db5d818e203ce180", 3593750 * COIN),
std::make_pair("d060683b4d765e1c4a6d4068d50e05c18ef70ada", 3593750 * COIN),
std::make_pair("4de2ea2fe1b800cd1f6eedfefbbb50ff99d06ca0", 3593750 * COIN),
std::make_pair("822213b77f51a65b6ca19e13e0f705a0ed695958", 3593750 * COIN),
std::make_pair("96e1667de2aee73bd3ee13e7e3593071ae7964b4", 3593750 * COIN),
std::make_pair("73dd0ab96d853de94c9e8260f61f73c807b8f149", 3593750 * COIN),
std::make_pair("0be87c3df9db89e112d9051cdffb62be58102e22", 3593750 * COIN),
std::make_pair("78754bd4e10a79dad5759f7e268a9de807fcfaf5", 3593750 * COIN),
std::make_pair("13a425b9af6e42cf00061a3e38744f36143fcbe8", 3593750 * COIN),
std::make_pair("f748b4ce483951e866fb0ebeacd5fee4093226d6", 3593750 * COIN),

// off marine priority fan outdoor risk unhappy apart pave hold found floor fashion entry display entry tiger dragon wrist around leopard cage faith burden
std::make_pair("dba01b4f30e4146cb33e544b7c9838d0c551c2b9", 3593750 * COIN),
std::make_pair("ad6503a59b02ff8aa2514be69a6cfbf7b8477a1a", 3593750 * COIN),
std::make_pair("3384b81807618d27eb73de32773bbd218f3c8906", 3593750 * COIN),
std::make_pair("254fe02bcfb852a9c6c17186d160afddc9d3bc92", 3593750 * COIN),
std::make_pair("4928fd21b9bf9e42b179bb9d182be443dc27bdaa", 3593750 * COIN),
std::make_pair("d9425ce37fda7223b953bf67cc7a08176b0f99df", 3593750 * COIN),
std::make_pair("94c3c1c5c017a8f94805d39f11dbac0ce2d96300", 3593750 * COIN),
std::make_pair("468e60ce35a75bfd7a03407f246915a7effe9670", 3593750 * COIN),
std::make_pair("bb129029974ba943075e0245e5d9b658c2d7e9d2", 3593750 * COIN),
std::make_pair("2f830b08ac9e4b5ccef4000907f975279915deea", 3593750 * COIN),
std::make_pair("d15502f76a7d49d9319af10e1a9ed464e1302600", 3593750 * COIN),
std::make_pair("0e817a6b34e173cc2171b6f5ab3783f572c4e7d3", 3593750 * COIN),
std::make_pair("c5612914bfb7e480ebd7572fe0e61171096a23f3", 3593750 * COIN),
std::make_pair("6d766957e2a40c874d6dea46993e2f89b35d53aa", 3593750 * COIN),
std::make_pair("d6209bc3f164543a3474fbcbc4d2c25584211507", 3593750 * COIN),
std::make_pair("ab3ce49396894adee9a9638a51c91677ceb1dea2", 3593750 * COIN),

// embrace clinic panther super various barely refuse various forget village scene mention bicycle reunion toast penalty syrup harvest economy toward metal abandon say asset
std::make_pair("4ce404cd3fb8ce371522f7e27c72917d9ac8aa09", 3593750 * COIN),
std::make_pair("8b2478c71e7160afa38e7fe4805c817136a4b78c", 3593750 * COIN),
std::make_pair("2df4ceb91092aace78c076adf434d76e18ec3d84", 3593750 * COIN),
std::make_pair("fee2f287fd4766b32ef1c4eaa1231768fb3a2ea7", 3593750 * COIN),
std::make_pair("36cdcd05d653c69690231a2eeb22bc9b0bdcefd1", 3593750 * COIN),
std::make_pair("661d3fb1f7f003c92de131b1bedbda10f0b58ea1", 3593750 * COIN),
std::make_pair("d0d85b5a96d53354a00cbe9faccd5d8fb407d959", 3593750 * COIN),
std::make_pair("168b080d4961766edd54e4a5669039aa32268d80", 3593750 * COIN),
std::make_pair("26837c41a73f014ef1ff0375e36899ee6169a278", 3593750 * COIN),
std::make_pair("0437781f13d78d524a58474494ae4200212ca6b4", 3593750 * COIN),
std::make_pair("949b432829e79d86ab718376dc797e1c88621782", 3593750 * COIN),
std::make_pair("b75c9284191f46c84841cd48edf5019c9ec16aab", 3593750 * COIN),
std::make_pair("39d2a45281eb3a6162c33e725f5fe79fd8153b5d", 3593750 * COIN),
std::make_pair("6bff36d7af9f900cdd2cfce7167c5f0efd377c04", 3593750 * COIN),
std::make_pair("776f67f16d3cb515fed1ec22232065377e92bf6e", 3593750 * COIN),
std::make_pair("002972e307462cbaa07f61ddeb8c0eb564de4404", 3593750 * COIN),

// antenna girl since page electric someone decline glance art grant bachelor behave rebel fiscal thunder rhythm reveal mail train soup pattern cheap accident jewel
std::make_pair("d8a4d72fdcbb12a115805124427605dfcb87e4da", 3593750 * COIN),
std::make_pair("817eb8cb767da999b9b627f6a002f31ca6c8000d", 3593750 * COIN),
std::make_pair("ae0ae36242836e0182ae29d42fe183fe7fe65e5e", 3593750 * COIN),
std::make_pair("6946176098e1d3d8d8b300b37f436e7a92009687", 3593750 * COIN),
std::make_pair("9aba2ad84d1be54ad207e508c399ac1b4a360d68", 3593750 * COIN),
std::make_pair("8637d2cde0fb7db65b3932cdde670e0d6348d904", 3593750 * COIN),
std::make_pair("4d90c75c851d6207b723edda6e921406b2147e40", 3593750 * COIN),
std::make_pair("4034202bae0bf4c386a7f4e137c46e3d8406c8b6", 3593750 * COIN),
std::make_pair("8142e7fc97542397f3f34a482fc916c3f547cb53", 3593750 * COIN),
std::make_pair("22933f943bfc08b0e4ab60b1c528efe64d9673bf", 3593750 * COIN),
std::make_pair("751c3844ca92ff29ccdac9b8357ceee79817849f", 3593750 * COIN),
std::make_pair("4c8b1d7cbd9d89cc2349255bc950d6fb13c25900", 3593750 * COIN),
std::make_pair("7d855d963723a232b0cc4b1d7a1a5b6c16cbb684", 3593750 * COIN),
std::make_pair("c8245b2a558b14a4bfebaac49d8235579d65bb9a", 3593750 * COIN),
std::make_pair("748ef3a23f7c10e5e4bb2564414f053a622955fa", 3593750 * COIN),
std::make_pair("5ea2de077ec6f1775d0f62d7a6799ff297c8844c", 3593750 * COIN),

// exact nation resemble soldier response wide voice solve frequent please fresh smoke frozen behave glare pear this diamond vendor focus olympic flavor focus what
std::make_pair("14e0b72ad6d2f414b6a62e4de7074105f3a8f028", 3593750 * COIN),
std::make_pair("b860273fb2b4dab81b57fbe1a9dfc2d1ed66653f", 3593750 * COIN),
std::make_pair("4f973052981ebf46c6948740a0c1b945756d3f17", 3593750 * COIN),
std::make_pair("c2d79307e4524073e7cb48f6dab5c5a3f40115d5", 3593750 * COIN),
std::make_pair("5c350f6150bdbc0fd3251981f57bbdfb55667631", 3593750 * COIN),
std::make_pair("3ec09f1673b0234475a6cdf1f3364474a9b66830", 3593750 * COIN),
std::make_pair("aecdc0dd5ab5cde207b85df660db0c1e9e7107c2", 3593750 * COIN),
std::make_pair("9aa8f047b23f4509d25d27fbeb9d2ebe90f03c84", 3593750 * COIN),
std::make_pair("a24aa61497e8622287ba6191796e213ef5fc64a1", 3593750 * COIN),
std::make_pair("5304f7343a31de031a3cf5b25445673d3ac25b48", 3593750 * COIN),
std::make_pair("6ffdc0cf7a1e7bdab0eeb00e2889518fc309ba47", 3593750 * COIN),
std::make_pair("55efe165f964201f150a9909e7fc587645d23da3", 3593750 * COIN),
std::make_pair("3c03c6325a98de5f8bb726d336aee8ad5ad51eb6", 3593750 * COIN),
std::make_pair("96061776ba1578ae7694085be038d05ba24c9670", 3593750 * COIN),
std::make_pair("60e857f847c7cc0fb6744ff7cf39f93327c56232", 3593750 * COIN),
std::make_pair("41be5c27db0e4ac2ce12e12f25254ea3e2d4afda", 3593750 * COIN),

// whip bundle arctic bird pepper viable hidden elite knife company monitor love sick afraid trumpet future bronze tragic party vehicle believe mule stick puzzle
std::make_pair("4b2c1b4f83113aa71cb193708ae424f88583f74f", 3593750 * COIN),
std::make_pair("16a27faece009c55047e20d63058f47fa8a61b20", 3593750 * COIN),
std::make_pair("b679e354f0b72e5eb6ee7b8dc1bcb1102f48f45b", 3593750 * COIN),
std::make_pair("4996bac557394b19a0e75ca064250641a1b4ef9b", 3593750 * COIN),
std::make_pair("5d420feb2f4b94c9e3d4df0a4e51910b46993787", 3593750 * COIN),
std::make_pair("24b776e1bb0a4b851933b0846f6d195602ab83bd", 3593750 * COIN),
std::make_pair("e48d9701102a197cb0a83129de92077c74b35caa", 3593750 * COIN),
std::make_pair("90f2960c9bbbfea9b823e00ef030a4380efc80b2", 3593750 * COIN),
std::make_pair("9c8ea5446daa3aea049f35e4946e39c6acebde78", 3593750 * COIN),
std::make_pair("935f630dfd641166ee3326c1ce381b6dc533e4c2", 3593750 * COIN),
std::make_pair("b9ce632e1375ad58ecd08aff04d09d48a0bc9617", 3593750 * COIN),
std::make_pair("2dd449d129f811cdde3642103f3378101b516bfc", 3593750 * COIN),
std::make_pair("dc32037a0dc7e75cacb68fb3af36b6d8f1617e87", 3593750 * COIN),
std::make_pair("3018d82966cbfe686b9701353d238bd82b0fdddb", 3593750 * COIN),
std::make_pair("ed8240a5b5771067750de950dc81753e743fa5dd", 3593750 * COIN),
std::make_pair("831d3b27742a872369fd337211b9c6eb69d6f710", 3593750 * COIN),

// post glass around resource april stairs peanut primary glass nothing front olympic kidney evoke hamster manage success slot faculty envelope napkin author diamond maximum
std::make_pair("6030938522119c56138b6d2eced0172b167740ef", 3593750 * COIN),
std::make_pair("1386da04378dd2b1cb0a9bca7cfe00fe226307c9", 3593750 * COIN),
std::make_pair("a48948cab1e2126845743a4fd1013b1fed398dfb", 3593750 * COIN),
std::make_pair("6a227fb9333c1086a0ade83fdc759777766364bb", 3593750 * COIN),
std::make_pair("b38200be3676f209a30e72e5adad2700ff450a46", 3593750 * COIN),
std::make_pair("b1fb64a25f5e817a4d4f5f3854a20493ddaacf56", 3593750 * COIN),
std::make_pair("261567a903e5a69d05a88e824a57b5f39ae6dedc", 3593750 * COIN),
std::make_pair("4653681722b0bd08dad7dc64fba44f292ea46700", 3593750 * COIN),
std::make_pair("2592a0e238d9a28ebabcc3b25ee5cabc98c188d7", 3593750 * COIN),
std::make_pair("b1bb079f53cc10e69b11d1be9511cefbb5d6cf6b", 3593750 * COIN),
std::make_pair("352d5c7e95f8e57ac7b56ef99fc67d6664574134", 3593750 * COIN),
std::make_pair("a3ca0ad403bcacf0dc83f7488c9f01afb06aea14", 3593750 * COIN),
std::make_pair("ab1cfb7a802b5acab38a36983db9d8d2111b34f5", 3593750 * COIN),
std::make_pair("f57d888a11932e37b55c2b882873332f8fa4eccd", 3593750 * COIN),
std::make_pair("f7faa9f4462bbfb647c3c0922acfa80cde123b14", 3593750 * COIN),
std::make_pair("78b23c213497ed3438d7ff3f498f1b9e76adb778", 3593750 * COIN),

// sister claw viable oven physical flee want seek brave leader fat balance pattern biology urban dish movie salon puzzle smoke surface illness surface uniform
std::make_pair("fdba53f2cb783d6c6f8bfdfa71dc98dc32f6b3da", 3593750 * COIN),
std::make_pair("4440c95491a1a19c9dc90e76508074ac6950b443", 3593750 * COIN),
std::make_pair("addb1afab0874db3983e0a640aa6375bd25bd1e7", 3593750 * COIN),
std::make_pair("1c9afccd090124b23d126931f357818bae45f0d7", 3593750 * COIN),
std::make_pair("def3cce00eebc9c17773d0c6c1e5cdea0af8a04d", 3593750 * COIN),
std::make_pair("9f8a3394dc961b35af83c6522fb6a4246a1ab99f", 3593750 * COIN),
std::make_pair("7abbeef8840727cc4c1871c001b2887d7f7ef5c0", 3593750 * COIN),
std::make_pair("2dc21787929152b1cc6320b80e5f353ae536f376", 3593750 * COIN),
std::make_pair("03a62e2d647b00b2d251bb7fb88a4c113dd102b2", 3593750 * COIN),
std::make_pair("9947f1b98e33684921c789d9b7ec372af74bd3ed", 3593750 * COIN),
std::make_pair("7d53c1e77eff40adc7f161f02d5752803bc7aa55", 3593750 * COIN),
std::make_pair("437b47b6948a5d8255ff3955159c579dd7077943", 3593750 * COIN),
std::make_pair("bf1c01ef7856ddecd865fbd911a99e17350cc1b7", 3593750 * COIN),
std::make_pair("9699023d350d7dbc00c382b1adb359eafa5a69fe", 3593750 * COIN),
std::make_pair("507fdf9fd9a46fec3857cd2c68cc3c6f98a4c375", 3593750 * COIN),
std::make_pair("9dc7ea98bbf2477b17b26d5aa01de010326f7b44", 3593750 * COIN),

// pyramid fury tired caution mean plastic nut cherry weird people scene slim record quote quality acoustic symbol tuition floor dove tiny creek dolphin sunny
std::make_pair("63ce29305a3a36e22a54c4a45e5c48ee436f32bb", 3593750 * COIN),
std::make_pair("8933f11ea7e07918d8eabca3ea7ea2012a40b47e", 3593750 * COIN),
std::make_pair("d5faee9765c8368bc0505293e409db6054a0b8cd", 3593750 * COIN),
std::make_pair("be7092d4b7ac1eb2cc07c1a0073065a20774bc4c", 3593750 * COIN),
std::make_pair("c1ad797c6cefc10c860cd7a5520a140b559c8d35", 3593750 * COIN),
std::make_pair("f42d2a9c3a7df429e905a07c6ddc7d4d5c5524f3", 3593750 * COIN),
std::make_pair("8af23e7bbb2d039923c350f563b68f55db300331", 3593750 * COIN),
std::make_pair("6ac40a7d971452bd0465fd07bfaed0c462ed052b", 3593750 * COIN),
std::make_pair("e9e10df579fbe197a3c63c6a3b6a9a9550fba254", 3593750 * COIN),
std::make_pair("36085d4add88f09844bdf8b7a7fb4e043be0ed7a", 3593750 * COIN),
std::make_pair("8d6948707147f59cf31abea5bde82f0041c83238", 3593750 * COIN),
std::make_pair("b10dbb6477ab44a7c67d06697f767551461147f0", 3593750 * COIN),
std::make_pair("232a7c7f9bca4d2a897a29116a4c78106ba09610", 3593750 * COIN),
std::make_pair("36ca564086699ad5a39704d41fcab2e72a9f788e", 3593750 * COIN),
std::make_pair("17dc94e9e389980ac299e232ad2009c2a4be7ff5", 3593750 * COIN),
std::make_pair("bd35911a9723d6e73c82c65f070ded18ff376228", 3593750 * COIN),

// lawn practice process flight become moon stand garbage spring enlist avoid such nest south north submit coconut tell smart render novel monster rescue vault
std::make_pair("79a16d93c85f4edc7294d8d34ca67b89cdaed2cd", 3593750 * COIN),
std::make_pair("28cf3ac4e93203b43928cec6a46c19ee5d26ae3c", 3593750 * COIN),
std::make_pair("d5e4703dadb50b58796d3d9f9c85a887badd781b", 3593750 * COIN),
std::make_pair("50be36f922b427260a582b30922657f9dc6ff1a6", 3593750 * COIN),
std::make_pair("d99a9045d6d2c43f37773a8aac19f24ee090c7e0", 3593750 * COIN),
std::make_pair("895aa35c0da29540d505f1a1c422f75a9b0bef27", 3593750 * COIN),
std::make_pair("1a5a7c4a4f1e5241e38f6eb38828fd13d1314af3", 3593750 * COIN),
std::make_pair("2cb7faa4aeb2755fc78c83d8a83c93909c0dbee2", 3593750 * COIN),
std::make_pair("c805ef8df37ca09a18d0239042b3d502932ebb77", 3593750 * COIN),
std::make_pair("0cc03df7c599616e7cd0055074a4f565b9df7124", 3593750 * COIN),
std::make_pair("69e85bac1fa492f545828c58f06eda7daafc112e", 3593750 * COIN),
std::make_pair("f98c0ab2ec60b99131f7a4084b5890d1d710da9c", 3593750 * COIN),
std::make_pair("06d0911689578e920caea126e54f3cfb8a63b14b", 3593750 * COIN),
std::make_pair("c826f27367fa305692197f9f66c0caa390805fbf", 3593750 * COIN),
std::make_pair("3e5134a72f9f826a6b6c824f70795de0459a9cd6", 3593750 * COIN),
std::make_pair("6ed15d8667fe8ac4703145543e18073f562f217f", 3593750 * COIN),

// dirt engage alter error battle forward crisp bargain tree endorse gospel elbow appear stumble alarm canal damage parade exile problem flower glove sudden like
std::make_pair("50271dc481a545994b17b4bef5ae551f06b7f7ae", 3593750 * COIN),
std::make_pair("a4f76f200d4d117cf4df01c6e30564f3a3d27e36", 3593750 * COIN),
std::make_pair("7bb22f2f9ba4cb0e1b1bb52beb8bdeadf3d5109a", 3593750 * COIN),
std::make_pair("a5079e03425fe149d87542e9790337bce22e2805", 3593750 * COIN),
std::make_pair("1460cd4449d32ff2bf0fc4fa3e258de0088e70cb", 3593750 * COIN),
std::make_pair("d3c8454ef14a0bd9a34716debccad9c197822b9c", 3593750 * COIN),
std::make_pair("44c1a003b8b796d0cba7d5d71a12583b53aaf566", 3593750 * COIN),
std::make_pair("9c21ed06b8fafe8a535f5a3904210cfc0cef480d", 3593750 * COIN),
std::make_pair("873a2018bc26f8b678bc0820d3f64814f90ced30", 3593750 * COIN),
std::make_pair("e386cfc4112d8958e27c01b40cb00f23fcca3da4", 3593750 * COIN),
std::make_pair("798865f044ac8c6a6a975933b9736e8b814e8991", 3593750 * COIN),
std::make_pair("df5ab4f04043a8c2d477ec2a71fec038ce48e7a6", 3593750 * COIN),
std::make_pair("24a057d695077001d7b6194c0bb363dfc8cde0c5", 3593750 * COIN),
std::make_pair("5a7061c9cf891b48a8326e446d54e9b406f56708", 3593750 * COIN),
std::make_pair("50f906d6437c0a81df4cae7c0114077a6db03102", 3593750 * COIN),
std::make_pair("3bfa950ac0d2ae9107d7f76a110819166f76d441", 3593750 * COIN),

// win soup moment hour picture enlist seek patrol bulb risk name program notice master promote gaze crash ignore general bomb ridge filter idle creek
std::make_pair("06b059698393e6b31eb505282e15252798c81d4e", 3593750 * COIN),
std::make_pair("ace9ee9e85ea44df6eccbea3dce87dab8d9b7a5d", 3593750 * COIN),
std::make_pair("40d1f9312d5e219669cb8bc82502066933af24ff", 3593750 * COIN),
std::make_pair("3e51e4b69e418552e0b78558b43613738e1b8ea0", 3593750 * COIN),
std::make_pair("eca1b0891bbd53e10944d276d66db612b989dad3", 3593750 * COIN),
std::make_pair("ef36b12d94c65c8357c9538385a3b0a3bc62c5ec", 3593750 * COIN),
std::make_pair("32321515b97de812650fe11644db967d1da90df9", 3593750 * COIN),
std::make_pair("9cea98e5d6bccfc26217cc73ede90a65fc2bc1c5", 3593750 * COIN),
std::make_pair("eed2b0d7d5ce632983bea55242f6552ca1510346", 3593750 * COIN),
std::make_pair("46ae81b67cc3a3947a0eeb0c1f58bc7fb62d3aad", 3593750 * COIN),
std::make_pair("7e44875fd06f354c14049641dc97e8fab066965d", 3593750 * COIN),
std::make_pair("75caef821ac0967695acf47a4a66cd2c201e65bf", 3593750 * COIN),
std::make_pair("82193a0f64b70c0e5e9730a0f25dc4b045df6c40", 3593750 * COIN),
std::make_pair("db4cc0d42a0b5ff01a34fca02f3a3645df85049f", 3593750 * COIN),
std::make_pair("a0e4bd04c84e14a1ed73fccf5e433a06a78ea3dc", 3593750 * COIN),
std::make_pair("df5320990de476635acbf8b89be14340d0670cd4", 3593750 * COIN),

// energy vault convince ripple dream month guide wage critic market exercise infant chef coach now meadow story absorb bronze world bless deputy bid upset
std::make_pair("c27bb0f8064368c1cea741955b879003df2ca9fc", 3593750 * COIN),
std::make_pair("840b3c2adf295df3421e4f55fd9d36dd09a59720", 3593750 * COIN),
std::make_pair("78637c133ca17e49765502433e4e6839cba73486", 3593750 * COIN),
std::make_pair("4a98394cd92299a1f3278f1780f562b9a10b7138", 3593750 * COIN),
std::make_pair("f58399289cfb3abe5333e5014e808103cca16bdf", 3593750 * COIN),
std::make_pair("1c073a3e75881896acec62209feee9044e70b354", 3593750 * COIN),
std::make_pair("2da8e0c0101122c0410977aed0325e00334ebfce", 3593750 * COIN),
std::make_pair("239fe17667ab024e4844913feb313703648401d6", 3593750 * COIN),
std::make_pair("0409eec2d4e411339de42183976c78c1377921d1", 3593750 * COIN),
std::make_pair("d0cf21b2cbbb62589ac89db1754009010a5f062f", 3593750 * COIN),
std::make_pair("73459c661f432c192d802d81f06e5e8159b424d6", 3593750 * COIN),
std::make_pair("cd6002eeb7bb6a72eae7eade7bf71d27112d9f55", 3593750 * COIN),
std::make_pair("ea61780b95a132b24a937f954911631cda16c672", 3593750 * COIN),
std::make_pair("2ef2f7dd5e22d04b42e92b2b40f5cf70c04c583c", 3593750 * COIN),
std::make_pair("7d625a70d1bdc5584e66a6ece6d978e67b7e4cb7", 3593750 * COIN),
std::make_pair("b2b51642265db016a6a62579626373500fb09e94", 3593750 * COIN),

// increase crater bargain fall time appear real problem wire leopard boring cannon flame sell laugh knee spy alone royal rain chapter forget runway slice
std::make_pair("e7da8a1f50bbad4700e009404b575a6899b438db", 3593750 * COIN),
std::make_pair("fbbad5e21f4b3cd32530f42d56bf1c1fb2b545c7", 3593750 * COIN),
std::make_pair("21b6113187d48f937e622052ff274f213da5724f", 3593750 * COIN),
std::make_pair("e1347aad0dbf18808ff5f29cf28413857512b197", 3593750 * COIN),
std::make_pair("2612247984f826a07cb1fbc77c094ce813f06fad", 3593750 * COIN),
std::make_pair("4414b005f28cf699224b5775cc1616ebfd062fa4", 3593750 * COIN),
std::make_pair("1839cf521b3a4d959b5e465940164ec0c22c4753", 3593750 * COIN),
std::make_pair("8df26dcf0f6bab0926d7ad3db1280fd5af2bdebe", 3593750 * COIN),
std::make_pair("5533ddfe2e22ce3fc2d8253de2c43acd8b687f54", 3593750 * COIN),
std::make_pair("dd3388f371d9e18b608491f8a7415f81a4fe37aa", 3593750 * COIN),
std::make_pair("ef1fc7b7d2f59626f408bcfac07322760665f8e5", 3593750 * COIN),
std::make_pair("b104a432b448a0d411da0d569748b4c600c347bc", 3593750 * COIN),
std::make_pair("6bb25313fa4601d3ccc343962ad30a9209e9d658", 3593750 * COIN),
std::make_pair("74488dc5cab2b66030d24e56353727224c0f0a63", 3593750 * COIN),
std::make_pair("371e5ba876edf626d061db8354881750af09a241", 3593750 * COIN),
std::make_pair("1215ee852e2f90d1006e7e07d27b86c221a74209", 3593750 * COIN),

// title scatter icon affair coconut outer stage broom interest lens wish ancient puzzle burger hen swamp grain mushroom cotton check degree mad tribe swarm
std::make_pair("d35b96e19c4cfbb04e98764a12621a2fc732e9bc", 3593750 * COIN),
std::make_pair("d4a473296e0e36368a21880a158136605455eb37", 3593750 * COIN),
std::make_pair("b691f3337c297417fc5ab094ddb432eac648ed8a", 3593750 * COIN),
std::make_pair("23a7ed1fdaa5536005a5d3dd14f1a9cbff96c53a", 3593750 * COIN),
std::make_pair("cd425a187b8feab39b2c1da60374a8c99efdd372", 3593750 * COIN),
std::make_pair("16a2939dd7790fb1a1cef9073d45726384dea5f6", 3593750 * COIN),
std::make_pair("4a913d7f6cfac5432ba553d74ab470b053985c03", 3593750 * COIN),
std::make_pair("768b6aa82891b1e2023e8467a27746e4d2b33e0a", 3593750 * COIN),
std::make_pair("198be2dfb4ecc62596351f1f6d7e5615def671c4", 3593750 * COIN),
std::make_pair("cbd434e9f27f4a5463e91dabe94bce5199d2021e", 3593750 * COIN),
std::make_pair("8c4e206c7491f766e9094bd5fa12a13de373f9f2", 3593750 * COIN),
std::make_pair("48c1542e2eacf0c9219263f0018dd4f4bd3352ac", 3593750 * COIN),
std::make_pair("69664de219742bf28b60853109ed18514537b1f4", 3593750 * COIN),
std::make_pair("9de93ab100a693cda449b4a5bbc659a48c40cb9e", 3593750 * COIN),
std::make_pair("01619457aa09db6c00177bd926d53f601601502a", 3593750 * COIN),
std::make_pair("de21fc06203435bef85690e7eb0bc4bed0da4270", 3593750 * COIN),

// armor photo wagon join hundred shrug fringe solid term pumpkin polar hotel promote fault reunion exchange obscure picture inch venture cactus seek youth impulse
std::make_pair("f561476cd89b322bda46b225f9bdeb36659c8d6f", 3593750 * COIN),
std::make_pair("91c90d228d7d82139bf023edbf30568d95cf4e87", 3593750 * COIN),
std::make_pair("5538db2aa565daaf0a1530d5c0103d4d0d188709", 3593750 * COIN),
std::make_pair("ffa17a7f8431c231064ffc1452bd5f457b46cf91", 3593750 * COIN),
std::make_pair("16a6c6fbcd2db2245db5758235fc1feecfdb2e7d", 3593750 * COIN),
std::make_pair("188d9bdb2baaae9cea8f7717b7a65b3bbce8c1aa", 3593750 * COIN),
std::make_pair("efa9cdfbc8abca5bcf4c92ea2697dc604b160029", 3593750 * COIN),
std::make_pair("d8cf707abc9e12448df0b38c0987ffb3e6085e6a", 3593750 * COIN),
std::make_pair("49ddbf4001aad1b767b7b61d0d6d8e2917e98478", 3593750 * COIN),
std::make_pair("f5a4d9a22752e7c79867a340b5b89fa024f216b2", 3593750 * COIN),
std::make_pair("83bb7d27fd14295bf989591e63dbed6a87c7857f", 3593750 * COIN),
std::make_pair("4d0d60e551589ac7af807ea992c9ecac7c4e0c9f", 3593750 * COIN),
std::make_pair("c900fce3539e7e98e4635deb2cb0a5f5ca8a802a", 3593750 * COIN),
std::make_pair("8f7e5d4358c273118234c8202b497cb7cba38308", 3593750 * COIN),
std::make_pair("afd224c8edb3d556d6ca7d4704e4150a1edce208", 3593750 * COIN),
std::make_pair("0c5b7f19486101bb9451e9235c148beea5208266", 3593750 * COIN),

// shift drive that vendor charge typical leaf sentence economy cream rain innocent gather velvet unique shrug smooth have water grow oval resist gasp welcome
std::make_pair("c6f87943557e1aa4915604626ef5d8f3987dcd93", 3593750 * COIN),
std::make_pair("e07b1d02ce416a27935a79531984c2e9ae7e8ed4", 3593750 * COIN),
std::make_pair("5e8e725ebb0ec05a134bab339fc82bd1ee7fafd9", 3593750 * COIN),
std::make_pair("4f3ca405672cd4e683746a62a30bc2b0aaa1c30d", 3593750 * COIN),
std::make_pair("75aa3fff992ca7720318acb7de0573670bb5a2fe", 3593750 * COIN),
std::make_pair("1c0b56a81eb3b4da9cb7543adbbf773975fdf862", 3593750 * COIN),
std::make_pair("af299ab2bbeef1ae66ee2abf82c6369cbfba95b4", 3593750 * COIN),
std::make_pair("878c945abbcf3006c6170402605a347d12f67ab3", 3593750 * COIN),
std::make_pair("f203f23abe0bb7839dc5389cc0837ddda495d5ab", 3593750 * COIN),
std::make_pair("0f6d3260601d11586bb515f2ac2a9ede9fadf8d9", 3593750 * COIN),
std::make_pair("e490d7d200bff97cc1b00f15c70e2719975ea1f7", 3593750 * COIN),
std::make_pair("e72caf467c302cd77b03f02f382eb8d6fb9b0a94", 3593750 * COIN),
std::make_pair("298980ef2976bca4ea3dcee85ba57c8bc9a44c4d", 3593750 * COIN),
std::make_pair("9dddd664c1875a8b7e21ec045510824ced7ff540", 3593750 * COIN),
std::make_pair("e32746307a9f052b08cd1848014ca7963f02f5a4", 3593750 * COIN),
std::make_pair("6d42f7cb472ec01120bb6bb765504cdd025bf228", 3593750 * COIN),

// claw measure actual smooth absent arena calm search category suggest echo umbrella verb hip bulk rotate hint pole wisdom private copy medal rail into
std::make_pair("655986d3f6be9f987460cb51b15a27d103a3b956", 3593750 * COIN),
std::make_pair("345cec41335b6228019cafa9e5745e3e5084182f", 3593750 * COIN),
std::make_pair("10c10a66d57190d1de86176d3c99af3fee23ab45", 3593750 * COIN),
std::make_pair("f4fd06fa98c4dc10d746f26bef0777199740aeb9", 3593750 * COIN),
std::make_pair("9329bf08c853286e4c989bdd2b20064abe84787e", 3593750 * COIN),
std::make_pair("19c5366adaaa6a6ca5a25aca14817ddd2dfebcf4", 3593750 * COIN),
std::make_pair("a1c6cf699c0d095399f1c6ecba36536d87dac9ac", 3593750 * COIN),
std::make_pair("578b4827d0f54d86e5a484c07e4e5c857a5f7170", 3593750 * COIN),
std::make_pair("48a8efb3bd854f04c49f15ce190452cb5e499ac1", 3593750 * COIN),
std::make_pair("431e4db19f2cd657e5643c5e0062101a4fb0a36e", 3593750 * COIN),
std::make_pair("990d362a32924d4bdebb1fec739defe846650f6f", 3593750 * COIN),
std::make_pair("047d1f9da3a4a55ca92f245d47eb07d9b6395978", 3593750 * COIN),
std::make_pair("973e18c7af9e5ac89219aee396a1a3a71dde4770", 3593750 * COIN),
std::make_pair("6c7036a44b87ebb9b820eb7ea1b71d68d040ed83", 3593750 * COIN),
std::make_pair("af42c12b1ae4b961af5475d3a4e0c9384dad1d9f", 3593750 * COIN),
std::make_pair("68e99e4faebabf2b8ced1a78a4da0bafb889110f", 3593750 * COIN),

// hard essay order shoulder spend rent december pledge main trim cruel pudding neutral blade media act nerve path shell ranch boy distance uniform hello
std::make_pair("03a87e4831586a873da9b03bb7f84bf9065b90a6", 3593750 * COIN),
std::make_pair("6375dcd7bb36f0315a3539b4a97b465069937d28", 3593750 * COIN),
std::make_pair("e5870dba3d1d31af47e4a07883cdf628b5b0b162", 3593750 * COIN),
std::make_pair("d9c2e3882c47ed7985d962f8bd1789db1c0c3272", 3593750 * COIN),
std::make_pair("fb4b2991e1162ab36a85cd6d96e016a7a247a7be", 3593750 * COIN),
std::make_pair("3ca78fa814673e1e9be784cf2ad45c4f8354dbba", 3593750 * COIN),
std::make_pair("a61f4763ff6b873f83f3333debdfab65377365d3", 3593750 * COIN),
std::make_pair("70c9fd2d7d098e29899f68f73a1bbd52b6fb417c", 3593750 * COIN),
std::make_pair("be3c2a0359faeada8b93fc48c99bd84cd37fc257", 3593750 * COIN),
std::make_pair("216b95e9d267cc4a435f58ee382441605020b1ef", 3593750 * COIN),
std::make_pair("ac8396b7cafd427b237b3f8cb1b9fd8dfb54bb2d", 3593750 * COIN),
std::make_pair("f53399107f23e9073f9cc57608a102e939eb1c76", 3593750 * COIN),
std::make_pair("99997c84f68b22e1340447eb973990d4b63f86f4", 3593750 * COIN),
std::make_pair("2aed6623a5c5d82f63a29b0a46da53db4c94082d", 3593750 * COIN),
std::make_pair("ce9aa64778b2f66b30a48905b66e43540050e336", 3593750 * COIN),
std::make_pair("0a0d4842a0c8d78c7f31f8d1ab6a12f60cc23ed9", 3593750 * COIN),

// excite timber wing useless effort rice coconut lamp emotion reunion run quality sniff prevent season broccoli elegant vast coin cry merry risk goddess bird
std::make_pair("a51789640674e718d23fedd8407db8ce58b4ad50", 3593750 * COIN),
std::make_pair("3ee25d167cc2a93b6cf0d62c0f92dbc28b57b366", 3593750 * COIN),
std::make_pair("95b7e67368a51d636ff3f70183a3a4adaace8608", 3593750 * COIN),
std::make_pair("d88352892a48dbdeeb1a0835bebcc7c130d37a1b", 3593750 * COIN),
std::make_pair("9006669001a64f204c4f5b241361866aaf8ee0e9", 3593750 * COIN),
std::make_pair("35f523d4ab75cb75d67233a4a97589fded4b2ab7", 3593750 * COIN),
std::make_pair("1899b01c7ce58c141d236444b24124e3b4257024", 3593750 * COIN),
std::make_pair("eccaeae49e0e9327d97d4da37219225b4b978e8a", 3593750 * COIN),
std::make_pair("25b860d8b86694549a0ef949408bd76ae1287308", 3593750 * COIN),
std::make_pair("f85c062af4ea5006ed6ba82f0b17cca3847d0dd8", 3593750 * COIN),
std::make_pair("f74073baf1600c15557feb512af93506f7e81390", 3593750 * COIN),
std::make_pair("e26f8e8803ae5bfeb8e3acea9cdb9cf02111bb27", 3593750 * COIN),
std::make_pair("c05abd599a6f311f2b8fb2254f9ed62f19dbc1ed", 3593750 * COIN),
std::make_pair("bf3a8e29a4e849be185374a0cb0d8f8565120564", 3593750 * COIN),
std::make_pair("6ddf45726770cd0ca506426ec3f616bfe4a72e3f", 3593750 * COIN),
std::make_pair("81bd7a75a750e9315566c650416bb82aec657b43", 3593750 * COIN),

// blur cube awesome ready shrimp filter normal mention autumn crazy parade quit bread game dentist zone kitten ketchup miracle wink snack senior wait shrimp
std::make_pair("4abbb690b48b4b6e2933ce908398debe34a9ddd4", 3593750 * COIN),
std::make_pair("e921932027525b717f9a9f4aaa9160cdd68d8dd9", 3593750 * COIN),
std::make_pair("e481c8c6a849e6bf96041e906c8ea9b16ed4fe77", 3593750 * COIN),
std::make_pair("43214d141a7675809e971fc191c188b4e3b4cf77", 3593750 * COIN),
std::make_pair("1a3b53fd11fb0f8e6dd9defeeba1455178d88d3e", 3593750 * COIN),
std::make_pair("e4a53131f6d3670aca22efebdf7efe30297dd3f1", 3593750 * COIN),
std::make_pair("4b7cfff6e69ffe988c2f6c20ccc25d1cda8685e8", 3593750 * COIN),
std::make_pair("894fc909325a958865916230137ade63b8f25f19", 3593750 * COIN),
std::make_pair("ec951ea632f6a842a5ff5fc0b4569f8b90817d6b", 3593750 * COIN),
std::make_pair("23de0fafe22c21b9ba431cc422d107c71c1f8615", 3593750 * COIN),
std::make_pair("cbe220c5f08e7a30920a08d5d04adc60212c293c", 3593750 * COIN),
std::make_pair("bebfc618279a7d52bb62d0d4c75479662a5c5286", 3593750 * COIN),
std::make_pair("e03c246697efac7081e84234304dc5deef6450b6", 3593750 * COIN),
std::make_pair("a131932feecff4ccce68c0b7be8d2990de043f27", 3593750 * COIN),
std::make_pair("23de43a527e184b7756a0855e96c8c689578d4f3", 3593750 * COIN),
std::make_pair("6aa6989529006b68210bd1fea8dad8244b9a3394", 3593750 * COIN),

// behind mask scorpion eternal merge craft thunder joke toddler fall mom debate describe soccer harsh motion embark cheap bundle chapter brass term letter scan
std::make_pair("0585bed12e7795340d5cbad919228b76b42dd6c1", 3593750 * COIN),
std::make_pair("d09ece329b33faffc8c9d8ea3e600a2cfa320244", 3593750 * COIN),
std::make_pair("f3591e96864dc6c66a063057e36364aae97bb841", 3593750 * COIN),
std::make_pair("795793e0633073d5eb08561e0ab9a80fc263f934", 3593750 * COIN),
std::make_pair("ae9a91d5f413ce0ac10ab6031c739a8d4c5fa590", 3593750 * COIN),
std::make_pair("14c28bb3ec3da757a3d006623a1196c573a70944", 3593750 * COIN),
std::make_pair("70ac936b1269fa45de46b6854e204dc7c73107e7", 3593750 * COIN),
std::make_pair("34aa0ccfbc7593c389ee402f540891cc62b29edc", 3593750 * COIN),
std::make_pair("8e90322fa6197aa10936b53bab4c8f88004b91bf", 3593750 * COIN),
std::make_pair("eba44c019dbdf416e306ff888f7ffb8bc0a1de81", 3593750 * COIN),
std::make_pair("7aad125002700a13c84308b65de752eb17254efd", 3593750 * COIN),
std::make_pair("954ce2c0fba30eccac53d66b4c551938889aed13", 3593750 * COIN),
std::make_pair("2d596c3e43cbaa1a91486fdb5e7ba0523378ca27", 3593750 * COIN),
std::make_pair("e3c2e771454aaa41b352f73eed3a91d5398227e5", 3593750 * COIN),
std::make_pair("508ae366b03911a21e3131d1a67a085311005e7d", 3593750 * COIN),
std::make_pair("554a6b7b9b48b2712355f72c3d12f480f8dffde3", 3593750 * COIN),

// romance sea spend road crop census increase route need liar library multiply float stove frost remember potato fortune knock lawn proof become pill high
std::make_pair("703ddca4e0c12cc222b0d5dcae4d6fbf54ff8268", 3593750 * COIN),
std::make_pair("44cc61ec981704a9052872b41b49ba428a693673", 3593750 * COIN),
std::make_pair("b21334c74918acc2aeee2b9c3415739c1cba7c21", 3593750 * COIN),
std::make_pair("ae23fdc4a285d327931b9a6ba82291dae680ef4c", 3593750 * COIN),
std::make_pair("84aba0ab1e96d7bc4d6af2451569a2e2e42bdbac", 3593750 * COIN),
std::make_pair("b2bd7ca9b0d99ebc07f498cc20a27250529a6479", 3593750 * COIN),
std::make_pair("deb6b6854d180400364e652b5fe05f7a6d830f2d", 3593750 * COIN),
std::make_pair("b49f9be40d2726a8e025b192401f3ab591e48a95", 3593750 * COIN),
std::make_pair("cd944aa74237d417153a29676cdd17588318ac8d", 3593750 * COIN),
std::make_pair("6f7aadceb41304f12bdd35105a9e51a4be328ee3", 3593750 * COIN),
std::make_pair("5bd4df64066e186a52fe21cda628f67698def66b", 3593750 * COIN),
std::make_pair("0421ebb3025b00dd004ae0e7081fd6b6952049b1", 3593750 * COIN),
std::make_pair("0ca422d013021b00028adec8c1377d70b1dd776b", 3593750 * COIN),
std::make_pair("46b1acd8d5a682f3dedc3a023593cc6a178f17d7", 3593750 * COIN),
std::make_pair("648637e6e24193d432825de4b0465f7bd3e3cc60", 3593750 * COIN),
std::make_pair("a731fd362ec2545eb79df321af9c0903fedeaf46", 3593750 * COIN),

// trend hundred fresh panic alpha hockey push tape monitor gas must beauty crystal trust ceiling super honey imitate gadget grant spice hen armor silly
std::make_pair("27629f8507ac2516214d1d48ef4071b5fd58e44a", 3593750 * COIN),
std::make_pair("af7ca14847d63ebc179d86579dda8c32f88f68e0", 3593750 * COIN),
std::make_pair("d3f79851027426f4bfac871798df1b3ccaf546a3", 3593750 * COIN),
std::make_pair("147c1eebcc65bb439477ef31d957d0534dfbe5de", 3593750 * COIN),
std::make_pair("7e080a80e012ea8af6639848c0c818954876daf5", 3593750 * COIN),
std::make_pair("0a59932fc77adaa2f04d0e290c61db3124a8a1ed", 3593750 * COIN),
std::make_pair("8a754174dc1304007bbb320a56401a30e7d277e9", 3593750 * COIN),
std::make_pair("ce9088b6991dea28f7d794d9ecc4eb8b2a157ebf", 3593750 * COIN),
std::make_pair("7d94d383f15fd25a4da555d815cb2c941037019f", 3593750 * COIN),
std::make_pair("783fbff46d5967a950200412d19ea9f6f36ac1d3", 3593750 * COIN),
std::make_pair("0bd64b1daf54c7f72da939ac5086a640c5039db6", 3593750 * COIN),
std::make_pair("af05db85d1b49c70429d316a398b57b54121afbd", 3593750 * COIN),
std::make_pair("8a0c359f976205641d74ac8fe32fed00e5e0158f", 3593750 * COIN),
std::make_pair("a76526fa0ea51ed9b82b5b2e8a6579797faa4360", 3593750 * COIN),
std::make_pair("e35b56491cd3037b3fc7fad427ecc9d5283b3702", 3593750 * COIN),
std::make_pair("a843f0ad2c0597fb8ea823e643cb1bb494253c9d", 3593750 * COIN),

// test reunion surface shell episode pattern filter junk basket venture exhibit swarm verify age patient amazing pave hedgehog undo shop amateur awake isolate young
std::make_pair("be85b8e72f35c8dcd48fa4e816f2bd479c8d7ef1", 3593750 * COIN),
std::make_pair("0cecc6735047776e9448d2f978772f46bb3a5a9b", 3593750 * COIN),
std::make_pair("06a2928a8f3b7d300f9517ba70de7ab80f2624a5", 3593750 * COIN),
std::make_pair("8d205cdfb5360ef86f79778e277b0a0ead933d2d", 3593750 * COIN),
std::make_pair("0c7449169733f40d0ce7cb452fbf4860bd012ad5", 3593750 * COIN),
std::make_pair("44f6de8ad62f9c31f528b836c2ca44b11a591e09", 3593750 * COIN),
std::make_pair("a741c71a1bcb57e558bb3954c25e20a2af71ce12", 3593750 * COIN),
std::make_pair("f5a12ff3d5e13c43b9a058fe560af81e35694740", 3593750 * COIN),
std::make_pair("f39095f8e266d5555199749d14e7239b025d08e5", 3593750 * COIN),
std::make_pair("4ae4f018a3e3ba83c76e7d7139523e5492be3709", 3593750 * COIN),
std::make_pair("e6224215794d8ad2eda42de494be73a32b1f8c23", 3593750 * COIN),
std::make_pair("97e1933f291de3bc9dc21bb7454a176578371b70", 3593750 * COIN),
std::make_pair("63deed610c70c4d5a832a399b739246e25b15ed4", 3593750 * COIN),
std::make_pair("f8c6c898b28c8d4f9a6b22ea447dffdb5791ecd7", 3593750 * COIN),
std::make_pair("5631d03306005080f33712e2427674ab172b1f85", 3593750 * COIN),
std::make_pair("ecab83ce31baa1b09afd2d7ec6995e5b50d63175", 3593750 * COIN),

// coil orchard harsh park border giant owner punch deputy sunny mountain theme combine pledge any unveil regret million fly fuel such switch visit time
std::make_pair("514354b835f5d839c0b62b368f6cf14fa66c84df", 3593750 * COIN),
std::make_pair("500d611479929b4b8803c97de0dfb56bc626d021", 3593750 * COIN),
std::make_pair("d3cee6d00ea05342e76864ace4a8681680b1424f", 3593750 * COIN),
std::make_pair("c3d970bf3b10d59dad7c9e2c687c5badb09a7ca3", 3593750 * COIN),
std::make_pair("d2d3636f772f9f3dab1851ba40deee1a866cace4", 3593750 * COIN),
std::make_pair("9c0213b145c623b0cfeb740dac991c675e00bb5b", 3593750 * COIN),
std::make_pair("4944516815ed0f8948fdff847ad26e1426c8391d", 3593750 * COIN),
std::make_pair("c36040e096fafbc45944cad86250bba49feb5d5d", 3593750 * COIN),
std::make_pair("a38e5e7051cdcf6178d3719b018f761f04afb431", 3593750 * COIN),
std::make_pair("4a4d72fc91f216cadd7c448ed56361dea9ce63ae", 3593750 * COIN),
std::make_pair("4bf0fd4470ecfc620e0f71cd51fc56fb025a7322", 3593750 * COIN),
std::make_pair("48cbc25b22c8721b2b124c788f73e3d38a1d1d0a", 3593750 * COIN),
std::make_pair("b154962b6f57c4b69ef8dc5e527ad21bd5efdca0", 3593750 * COIN),
std::make_pair("977936f57babe4f5a35161423a66aeb6c34101ad", 3593750 * COIN),
std::make_pair("80ade0e956448f85ee34fd6ad275187537fefe61", 3593750 * COIN),
std::make_pair("70f58ee949ffaf8fb55447efeef560427c6538bf", 3593750 * COIN),

// spell fall art aware flavor earn bean logic dizzy you alert episode vacuum zebra camp scare deer file marriage mutual doll donkey screen candy
std::make_pair("2941a67657a67abf2c4cbebcf565f98a6829dad5", 3593750 * COIN),
std::make_pair("797152afd420c5d6451624b56eb7f88137e9a9a2", 3593750 * COIN),
std::make_pair("5e8ee6c19a822feac0be2e340809a3b14259ae0a", 3593750 * COIN),
std::make_pair("6df36e3c56c6ae54f814753d51e42ee993aef53e", 3593750 * COIN),
std::make_pair("a958fdf72497c0325461b392f5536ce41d2515b4", 3593750 * COIN),
std::make_pair("3f9c1f64d68efe75e98f15b07ca40f5216d4e07e", 3593750 * COIN),
std::make_pair("c0b466605d04d166e1a1ff1078ceb918204bf4d0", 3593750 * COIN),
std::make_pair("c2b6d876efe2902a17c2e1b1171329e1ee51354d", 3593750 * COIN),
std::make_pair("615c53b86bad167ff47724e6e17873747eb53cb7", 3593750 * COIN),
std::make_pair("b7030549bff65f338e19136833d7c1d31e596510", 3593750 * COIN),
std::make_pair("bf935c959df09dfaa49292129da2eeef19fb254b", 3593750 * COIN),
std::make_pair("5a81acae4befa03ad4d92eda69e1a48506dc58d1", 3593750 * COIN),
std::make_pair("4dfb6347821c9cb2a48541d1af4544fb76fe287a", 3593750 * COIN),
std::make_pair("a09f48a70eee8039177ba350cde629106d90161b", 3593750 * COIN),
std::make_pair("d165febc455e467617ffd5e930e387abc6d3d9df", 3593750 * COIN),
std::make_pair("0fae267dcdcbbb2c373168c026243a756047f591", 3593750 * COIN),

// black merry off metal spin west chapter main mass bench diesel okay amateur bunker barrel oval exchange banner fish aerobic theme two office lonely
std::make_pair("8d5b9e3492d13abbb0c43a76ead5df6b17f2c9a2", 3593750 * COIN),
std::make_pair("4a28bb2fa9c9e3828d1aad5910ad037fc2316b98", 3593750 * COIN),
std::make_pair("772f1932564d040e148dd2e1436e4409ef5bef0a", 3593750 * COIN),
std::make_pair("31d4a92f182d27c69105a9387604159dbea5573a", 3593750 * COIN),
std::make_pair("474a89e7dd3a99e755a78d42825ad464bd55287e", 3593750 * COIN),
std::make_pair("298b316d95c6d8bf667ec62b53b7fd352f3abe4b", 3593750 * COIN),
std::make_pair("38ae73e239b33f2972399ccfae95f046db54338f", 3593750 * COIN),
std::make_pair("2b072431d4f67a60eab4f08bff9f715ff54489da", 3593750 * COIN),
std::make_pair("6d5ddab5df551e565bd180d637856fe3b1a02f5e", 3593750 * COIN),
std::make_pair("0c02aa6b3fea46e3975c8d9e4e0bad868c03e099", 3593750 * COIN),
std::make_pair("c95fa8c7ab03e144b778d059145a35088a3c951f", 3593750 * COIN),
std::make_pair("12f491018237071993eee50c7cae61bec35bd093", 3593750 * COIN),
std::make_pair("cd799ae31ee44513363b76abccc414d401322f14", 3593750 * COIN),
std::make_pair("9252e000636de5ba02eec695d5fac6140c5ca985", 3593750 * COIN),
std::make_pair("cbd221fdc6d35195b877f02d7de8f146d25340fd", 3593750 * COIN),
std::make_pair("d5dbcb34d286bf73671007a8d11c70ca27edbdb5", 3593750 * COIN),

// mystery dolphin bacon fortune hospital jacket glance clip virus jeans mother forest equip tool silver artist twin pink address harbor stable shock horse boss
std::make_pair("4cb2c13c91901bcb1c7ca2b38479d0b78a772a93", 3593750 * COIN),
std::make_pair("e832ba6dc924e312e672f2c6165981fcee25fb65", 3593750 * COIN),
std::make_pair("2b6689745e7ed7722a7acccff36835ac4a8bb0be", 3593750 * COIN),
std::make_pair("edcf4bb79152e7a923fe518a93f3fb7a5fe3a93e", 3593750 * COIN),
std::make_pair("d161340739c5f534ab9b6765537e02c191a6a47b", 3593750 * COIN),
std::make_pair("6314736667ec45ec512323ac57d094942288db00", 3593750 * COIN),
std::make_pair("700f760332249676761baa596ea740d33b9c7e1e", 3593750 * COIN),
std::make_pair("08c8223bf7b7166c4e8967effef2698f4d7d04d8", 3593750 * COIN),
std::make_pair("ec66fd8ff13e08ab24e009dadef65fb878cbe9ea", 3593750 * COIN),
std::make_pair("e0fca54a825cf4d45b46459cde840cd447c70ec2", 3593750 * COIN),
std::make_pair("0333f6808c0bd82d983053e84b823a2baa203644", 3593750 * COIN),
std::make_pair("78c8cef9a63e71e0847e47f09faf2609e63fb337", 3593750 * COIN),
std::make_pair("9c7cd99420024aae417b867a3a8242648756c791", 3593750 * COIN),
std::make_pair("5b4f0d825a2a390b857003684accdec4f13ca2f1", 3593750 * COIN),
std::make_pair("833b6e0392d60485d85795c969be55a8d21d313d", 3593750 * COIN),
std::make_pair("6df4a6c1eb945bc44e3e38c90ff5d90c3e216712", 3593750 * COIN),

// body treat stone weather crime expand vehicle wink crumble priority unhappy matrix enact occur often magnet lizard effort return blind deposit choose toy physical
std::make_pair("9f9f712205d3c269dbe008916195cf0f39c45465", 3593750 * COIN),
std::make_pair("f8fa4030a2e15598acdf5142f658b45efd5d15b8", 3593750 * COIN),
std::make_pair("e048bf3b6e736b5bd4d28e3a30044d5341ea6468", 3593750 * COIN),
std::make_pair("f92e9ca134d5398501f995fd7ea6c7ba1a4e14f1", 3593750 * COIN),
std::make_pair("aa0754ca44fddbbaf35a6d5e8d8e0553434850f4", 3593750 * COIN),
std::make_pair("d713594433005611343a7c76b30d47bf0a8c2839", 3593750 * COIN),
std::make_pair("af729ac71f5bcf34630d48211fa450d60873614f", 3593750 * COIN),
std::make_pair("d59d91e125b067a3ba3536436cf45a8d8e3669b2", 3593750 * COIN),
std::make_pair("3844c4e4be9c9e7c287d7228a1d94f6e3274615e", 3593750 * COIN),
std::make_pair("60e3db2db1f81133bac87691d0e997bec0d28e35", 3593750 * COIN),
std::make_pair("e2040149a527b6edd3f9b8474aeffdad485f046f", 3593750 * COIN),
std::make_pair("a21aea8076992e0e3bbf92c4e323dd18b1313a1d", 3593750 * COIN),
std::make_pair("8dac6532332ce870d7b84ce22a4b393c600dfb2f", 3593750 * COIN),
std::make_pair("6f1a57864f8e93ddccb6e3027ab1df4c8d9f0081", 3593750 * COIN),
std::make_pair("395a61ccdf62354ddaba84fa801cc64296d43fd7", 3593750 * COIN),
std::make_pair("ebb5773fc0244c5b4defd088b298e538582008bc", 3593750 * COIN),

// taxi carpet sheriff explain require step legend patch sketch pull rent chunk improve aware jazz mention amused return poet that once snow grace copy
std::make_pair("72af4ef77707b975b3ea6563f5edf439e32cc7a6", 3593750 * COIN),
std::make_pair("54d5172facd69239b1a42d60d9690d5d7bc37881", 3593750 * COIN),
std::make_pair("d7c6b537d209fc675bc014d409fedfd41deece23", 3593750 * COIN),
std::make_pair("8ee1cece68f0d73d57a14f33b36130b641473e04", 3593750 * COIN),
std::make_pair("696bb22ff6a0d64f0002319cdd9620788d097b18", 3593750 * COIN),
std::make_pair("c1b240ba942fd67683773580b0f28deb1b1a8f7f", 3593750 * COIN),
std::make_pair("c3d5e7993039fe831f047acb97d56e34050b9130", 3593750 * COIN),
std::make_pair("7835a507b5b1893843cee3c61c3039aa99e37e03", 3593750 * COIN),
std::make_pair("abe2949c37ba0584e845abaaae811c9509ccecd4", 3593750 * COIN),
std::make_pair("264f9e515c879dcfcbb82e81eefdce0438fa3235", 3593750 * COIN),
std::make_pair("435ebbe6d4fbe97e305ea60d7ac2ce6e4f356855", 3593750 * COIN),
std::make_pair("be827de88f94a143349dc496c480a6ecbe5a1d0a", 3593750 * COIN),
std::make_pair("3ce17fc2b85e0ea113de3a531a07798c586e8143", 3593750 * COIN),
std::make_pair("bcadd0edfcc6e355191bdb4b271e5d6514d2ac79", 3593750 * COIN),
std::make_pair("3585459f85052632c6922dfe7c6c3d88e545ba91", 3593750 * COIN),
std::make_pair("27e633244d560ea2b616741d948529f284eb1b04", 3593750 * COIN),

// response return maid flag scout sight mandate original common sunny involve together flavor joy bike trim calm able ozone punch vessel clever fade brown
std::make_pair("84645d4d333172fca8925e7818adf367540062fc", 3593750 * COIN),
std::make_pair("55c7f30f1645649491d602411c51c900b50dc845", 3593750 * COIN),
std::make_pair("e7557bbe380eef91c5034c40edd0dfa85e7834f4", 3593750 * COIN),
std::make_pair("1b695872d4420a10b648818cb082d8a37f8bfcac", 3593750 * COIN),
std::make_pair("94b7e068769c08a0856f7b951375547a338a1bc9", 3593750 * COIN),
std::make_pair("620982cbc0b9139938fd3866aaed5c3e4efea98a", 3593750 * COIN),
std::make_pair("3dcdaa9667098f48dea2fb35c7c04b7fa6194248", 3593750 * COIN),
std::make_pair("95c6bb19792bee52dcd593dbaa00a0a64f65c09d", 3593750 * COIN),
std::make_pair("77e3596f38692eb0b46208bec10fa027c2a5c6fb", 3593750 * COIN),
std::make_pair("fdc876264f380ffc3d8810a831a22ae1a6015500", 3593750 * COIN),
std::make_pair("d520127f7665b30fe4ccfdf068b9c6b1a018e13b", 3593750 * COIN),
std::make_pair("a12fff295f7fe9d1ce078cb302ad0f82f3a65c21", 3593750 * COIN),
std::make_pair("3dfb21d8a7de5065ab8bd21b510681a4c3c2d9dc", 3593750 * COIN),
std::make_pair("40e9ca4971aaa68f1d3ece0625e003cb69a18b2b", 3593750 * COIN),
std::make_pair("e93cdd82ebdafaf0bb7aa9d98b9c8e644f00bdad", 3593750 * COIN),
std::make_pair("e330186ae1f91e1147e199401b55c6ef842e7612", 3593750 * COIN),

// often phrase jewel grocery absent mother teach forget piano fossil like cement tilt front arrive obvious burger enough direct estate arctic crazy domain slot
std::make_pair("d3eecd23b081163d07405b1425082aee5ec1f12a", 3593750 * COIN),
std::make_pair("ad642cc022b125a5b36699d9b059899ab7051538", 3593750 * COIN),
std::make_pair("56d79f5ffe43d56f6e5669b68c9b385f40fb1dcf", 3593750 * COIN),
std::make_pair("e90096733b676bb1be0f418400178012da409d03", 3593750 * COIN),
std::make_pair("515c1853cd38649856fee334a3d5c8193639d52d", 3593750 * COIN),
std::make_pair("eb3bdc3e9a03686b564efbc1adaec194e6425849", 3593750 * COIN),
std::make_pair("9e53bf07a55475c2b0d17e26c7f95d5a01d032e3", 3593750 * COIN),
std::make_pair("20b39317a57941e8e924170e6296448dfdebff3d", 3593750 * COIN),
std::make_pair("22906f470094a7e24ac9322e0df5a8163bdc6d90", 3593750 * COIN),
std::make_pair("86c15f1f109ec5d614a076d0f80252079b0c6c0d", 3593750 * COIN),
std::make_pair("3b82e37595b60c63f38815d1335f480a1758f9ae", 3593750 * COIN),
std::make_pair("6e9451315e6d2330bea9da6728b210e067dc5e8a", 3593750 * COIN),
std::make_pair("1f8144705c0b3d5f3feddd941af8dace573f8fdb", 3593750 * COIN),
std::make_pair("a05cb7992e732e40af44da8d23987970be3c3eb0", 3593750 * COIN),
std::make_pair("01a0dfd52cb8d5796b2b0c0d6145c5b8937a9e90", 3593750 * COIN),
std::make_pair("ce8df499b2848694fc42920dcf1773b8ad43b530", 3593750 * COIN),

// flash ten option trap catalog victory brave critic regret idle supply worry hen sweet code grain chapter drastic scheme salute february party harsh chase
std::make_pair("aae17fecd98d84e9d3974e9e96d11d100c16bd60", 3593750 * COIN),
std::make_pair("2e50f67772cf889d0d2b5abadc3881e2e2d6325e", 3593750 * COIN),
std::make_pair("67405909d0d40c2294604323ca8eb970c3e374c1", 3593750 * COIN),
std::make_pair("1e43a89fa6b0af7843de007d9f0753890136432b", 3593750 * COIN),
std::make_pair("4259e9fed4e7c4cc9e48e15663baea85edac486f", 3593750 * COIN),
std::make_pair("8a0ea13a9247ac18397be59715b700b656935501", 3593750 * COIN),
std::make_pair("83e4797bd72b92294b765ba42a4ea51fede8a604", 3593750 * COIN),
std::make_pair("e29bbab520d2c46c23e5c9501d82c61a968f42b6", 3593750 * COIN),
std::make_pair("78f7e61d33d5a99af3cd1861ee10cfefe963774b", 3593750 * COIN),
std::make_pair("bde7d3475dc8d03b16d4bae647dcd99dba72cc2f", 3593750 * COIN),
std::make_pair("12e3c9d6882da0d76513e1aa8fa8ba3cf863d542", 3593750 * COIN),
std::make_pair("d8273f356792ac37ecf304822d622ae45c7d532a", 3593750 * COIN),
std::make_pair("a7791f545f34c993098cee5bf1c0dfb1a2c1c313", 3593750 * COIN),
std::make_pair("9dcff4716e61232e5b6d4edfafa2c5bef68d1e8f", 3593750 * COIN),
std::make_pair("c75a4c4ca7f685b9b3df3ba00cf2c15d1cd8c437", 3593750 * COIN),
std::make_pair("fb61930022839c23d3bbc3b7cde14f83a64d794b", 3593750 * COIN),

// upper magic love ice deer pupil group maple broccoli athlete satoshi aisle pizza slim you ripple blossom screen prison bring job cabin deer age
std::make_pair("ad77278b8f8fe44445acce96ba02d0577f268676", 3593750 * COIN),
std::make_pair("a2fa0ba48bd0f9dfcd2bfb100ff2c9dbe7add498", 3593750 * COIN),
std::make_pair("e46a2406da2fbb6d1e29c3e28f7d440245b9cfeb", 3593750 * COIN),
std::make_pair("da90763988bb70883dcba26c6f8823c0306aa9a8", 3593750 * COIN),
std::make_pair("bcc281e1c51d3281e2edcd9b5b3c2a2042b91417", 3593750 * COIN),
std::make_pair("89e5f0e5d3b1a61f03f57d7eba46c284bdadd7dd", 3593750 * COIN),
std::make_pair("88ac1cbec0d30561ef0cc7967264718b76555148", 3593750 * COIN),
std::make_pair("ed4da3035b5e96b0479268ebe7d442fac2f0865c", 3593750 * COIN),
std::make_pair("ca6bd214a7cac82f2032a8cc30d6e700bf971164", 3593750 * COIN),
std::make_pair("623647cd2a28463e337edc21de873da0150cd0ef", 3593750 * COIN),
std::make_pair("f6b227a674ed2ca5b7bd0fed5b516ce3461c9d2f", 3593750 * COIN),
std::make_pair("c9624c1ebebcf13dae5fc83c41c22469c9d03808", 3593750 * COIN),
std::make_pair("80c7303003326ac26f6ac68c4e5d445ea6286368", 3593750 * COIN),
std::make_pair("504e32f81478411025a76ac409486d12ec03de32", 3593750 * COIN),
std::make_pair("888883446c030ba22a031255fdd69f38d5353482", 3593750 * COIN),
std::make_pair("9899d27e55d3f0b38e04ffe0d75b3c8b8dc738a2", 3593750 * COIN),

// scene math coil boss axis photo rare undo ritual elegant excuse fly coil metal distance fruit illegal memory square bring joke artwork label chef
std::make_pair("356fbc93fbb4b425413ea26df0918658ee81ed43", 3593750 * COIN),
std::make_pair("b91baf3da564017a913bb67ea4861874f58525d9", 3593750 * COIN),
std::make_pair("1f5a855260bc165145b13c2c8f2214ca3ca19d18", 3593750 * COIN),
std::make_pair("06a24b3404f8ec70fa390e8ebb3e42efd6a7ee32", 3593750 * COIN),
std::make_pair("de054b40fba5bf6ad78c6912e9105c8a9891308d", 3593750 * COIN),
std::make_pair("079463b6870b1268ee9f65e1eccd54b9f47ca49f", 3593750 * COIN),
std::make_pair("989587297bfb431beab1fec02e491341f68d9d07", 3593750 * COIN),
std::make_pair("3d0cd82ed14fcb34ede0f88d2630e39ce81f3c99", 3593750 * COIN),
std::make_pair("179c9f7dae397abcee89bddc2f2e9b6f88c6b701", 3593750 * COIN),
std::make_pair("2013a75b5a8beba799f2438b198672e5f114fe11", 3593750 * COIN),
std::make_pair("a27875b55138c18ffd87aa439c0596016785c2fc", 3593750 * COIN),
std::make_pair("0ed3be21e73edcbd17f57bd9d7998e644e089d38", 3593750 * COIN),
std::make_pair("d78ef12b341bc8582ca89281e50c208fe6a32f97", 3593750 * COIN),
std::make_pair("f4ec9dddc6077cb7ad91b67be830510e6c4cb648", 3593750 * COIN),
std::make_pair("15de00b45aa52f5b5efc216b5d75c9d0d6d1b682", 3593750 * COIN),
std::make_pair("ee50d08c6aa9776ed1702d43310540eee8b88901", 3593750 * COIN),

// spray twenty east author day napkin finger ignore bean devote invite setup above filter depend embrace funny young rare craft quote stem deny naive
std::make_pair("36f65e521d0e3c97145ae43f211837073b404d4b", 3593750 * COIN),
std::make_pair("18796693823d719595e438e0771b52425d07ae38", 3593750 * COIN),
std::make_pair("a3243817ba8bfa7b04ac0fedc26ae27daf1d6b1e", 3593750 * COIN),
std::make_pair("a050033bac8aaf0b3a04a1fde39f4d40931c5256", 3593750 * COIN),
std::make_pair("0ff20922d5c62f50093cb20a6130071f8d4a8991", 3593750 * COIN),
std::make_pair("d4d02c28156dd2af59796d2391622f31732ed7c8", 3593750 * COIN),
std::make_pair("6717f8d2336bf5ac07427bca1d6cd2e8d3cfbd51", 3593750 * COIN),
std::make_pair("fd05f5e35fdbdda262c8f69cc06c72ca503da4a5", 3593750 * COIN),
std::make_pair("bacc8e64ad7765b3b28115eccd5f6af904443e79", 3593750 * COIN),
std::make_pair("16d13ab5fe271246e2ee334c67d826858f94a718", 3593750 * COIN),
std::make_pair("14d0ed3eb3797aafabaa94af3605082aa76fd9cd", 3593750 * COIN),
std::make_pair("38e9c9c959febc26eefec3bf8e1ed3b05c7549da", 3593750 * COIN),
std::make_pair("cc916801033fafb5f6c5764e24c3d2101c43bcdf", 3593750 * COIN),
std::make_pair("90a0304d36c7c9bab111a24015a21f15147efa8c", 3593750 * COIN),
std::make_pair("f2c5fa4805459aae1900cbfb652b11e7cb1ed94f", 3593750 * COIN),
std::make_pair("53869a4a538b2c7aabe9b77d890f866b1dd616b4", 3593750 * COIN),

// truth size blanket alley rebel future income morning depend harsh electric extra arrange size once mule hip pretty behave column roof fan volume swim
std::make_pair("0351a08c626c9770a7671c74b25096751b8c9622", 3593750 * COIN),
std::make_pair("9bd86a98a564c85b11b6bab64d91a1a49c0c1b9e", 3593750 * COIN),
std::make_pair("a5ff7c5d8f0bbd5a2edd269914a7f2d96f18e884", 3593750 * COIN),
std::make_pair("331654e2082d4821b847edd6e5268303e6dbc2e1", 3593750 * COIN),
std::make_pair("0e92875ac0855902207ca2b9ec053db7232b464d", 3593750 * COIN),
std::make_pair("3421102982d24bd69e53b80e0da3faf66779bfbb", 3593750 * COIN),
std::make_pair("1ada0ee24c7ff18fcc7622cf2ba8ebdf107da473", 3593750 * COIN),
std::make_pair("97dc0370043968babe06fc5d81ce2c12f366cdca", 3593750 * COIN),
std::make_pair("cdf9ab8f545fe52176e1ebc1724a6c29ff3d49b2", 3593750 * COIN),
std::make_pair("4748a83b6cf62d9932e6781f647db2e5e31dc77b", 3593750 * COIN),
std::make_pair("a5fc187841f973b1628b175f24c5a686fc2f11b5", 3593750 * COIN),
std::make_pair("8991a13ea441fa919d4330bdc6c2c8a3ce6be639", 3593750 * COIN),
std::make_pair("e80a9bc3e9b2fc3b3a4aa5d3b9e9d6de93912de1", 3593750 * COIN),
std::make_pair("efe07195e321dede6de8930d8985a4f3faaab386", 3593750 * COIN),
std::make_pair("27d389152f13c1424cb785ed7c26dc4d9a6e8a50", 3593750 * COIN),
std::make_pair("362c06b4e87fcc8a8c39e70fedf6769c214b8833", 3593750 * COIN),

// tray eager sail toward drama canyon muscle mom drive march rookie bottom talent crunch spawn primary catch buddy essence hope present parent emotion weather
std::make_pair("24b177a6621f8eebd236117cf7865d9a2b94f94b", 3593750 * COIN),
std::make_pair("6f16db65144663bb72fdf713df1927f61f8ed4bb", 3593750 * COIN),
std::make_pair("f659c15056bca3aa006014e5193772820eac4d38", 3593750 * COIN),
std::make_pair("2968ad40bf3fe5ec622ea1dbba81de76779faa40", 3593750 * COIN),
std::make_pair("7330ceb0ca754d529515500615dfc2bc401d3e83", 3593750 * COIN),
std::make_pair("22dde07d8fcc277ab355188ab7c97d6922beae0b", 3593750 * COIN),
std::make_pair("47f9f811f5af6c57663d7a9fb8106352d7102458", 3593750 * COIN),
std::make_pair("fd5ae6d35f38a74901280f4c4663a12f4d282952", 3593750 * COIN),
std::make_pair("22c8dd0c6576f0e80c3315457172fc797a730b36", 3593750 * COIN),
std::make_pair("745986a6c4fc2c7dd7cc54041b619e48819d0fed", 3593750 * COIN),
std::make_pair("6545018923dd38d507ac132e598a8e01508c334e", 3593750 * COIN),
std::make_pair("0f00e30f61e2d5fb77592eb4d117ff91416e7952", 3593750 * COIN),
std::make_pair("a0cab6938bb966d251daa9220020c31e699aa892", 3593750 * COIN),
std::make_pair("f33dc0c11f0dc00836dcdc73c2d431648f08b4b5", 3593750 * COIN),
std::make_pair("3e3042c01da58ffd9ae7bc6f8a0bebc9fb0e2084", 3593750 * COIN),
std::make_pair("3251b40d1e1804e347b59dffbf314f22945617c5", 3593750 * COIN),

// turkey sick pull spatial lemon execute orbit razor bitter pony inform fork more amount trade matrix world miracle dilemma custom trophy put fatigue endorse
std::make_pair("338d2648460c1e114117c55eec46ba34cbd431e7", 3593750 * COIN),
std::make_pair("84abbd234e59fcba7b1ce157f8208f83d0c40eb6", 3593750 * COIN),
std::make_pair("f830b4e6537123313778f818d2a0add524cdfa52", 3593750 * COIN),
std::make_pair("66ae1835cb326f09abe526e71034aebbcf7555ba", 3593750 * COIN),
std::make_pair("e790976f4a2d95d31f424a4dc5fb73660cea8c3c", 3593750 * COIN),
std::make_pair("6c1204f1bb8fae40d0d0c924eba576c4b00a5dc4", 3593750 * COIN),
std::make_pair("de654987120bc2cee04b25a79d654c186a3b7d45", 3593750 * COIN),
std::make_pair("e0eb566f93a4bc80949db93c68a5f886d6691a97", 3593750 * COIN),
std::make_pair("da205b58977b5c0a7d75e5d8143347d633909157", 3593750 * COIN),
std::make_pair("2719c6e1f3337c9ebc613d74145b62c6ec84a46c", 3593750 * COIN),
std::make_pair("d9e99f1b0a147f8b1efad4ceeec385486589493b", 3593750 * COIN),
std::make_pair("33014067903448fd6151bc85b278db1065d23a2a", 3593750 * COIN),
std::make_pair("27776cfd8e4e914480ba00c144add826bf306aef", 3593750 * COIN),
std::make_pair("a3dd56b5210394e189eebd2bdcbfbfda0b881709", 3593750 * COIN),
std::make_pair("9b4a8e4235ea996d90bc9166072fcb90c690ce2e", 3593750 * COIN),
std::make_pair("4b7e68fefd1126bcf6f3052e10fb75cc7f548979", 3593750 * COIN),

// middle desert twin wage awesome friend patient virus wish fan rival wire remember sunset side crop like grant blade cannon corn uphold maze detect
std::make_pair("65254dcda5c9fa5b036c44498268fe8674f85a0a", 3593750 * COIN),
std::make_pair("b6380fb73411bad8f92721e718ae204bfb969bee", 3593750 * COIN),
std::make_pair("fb2750d3a12bbe5535854a5706be02942649da6a", 3593750 * COIN),
std::make_pair("4baeb7470e71f0ffa799ba5098c3dca8cd7eb279", 3593750 * COIN),
std::make_pair("915a4fa2187d16b0935f5bb7d56544bbd6692887", 3593750 * COIN),
std::make_pair("0864339a1d87b46b0e535b8966e271daddfba3e3", 3593750 * COIN),
std::make_pair("d051774dbb1c36c7211a5bf7913508753e73e218", 3593750 * COIN),
std::make_pair("d8a1a9f236a94fc220b2f1598a133f3196dbea03", 3593750 * COIN),
std::make_pair("73001e4e58ebfc3a7b9d0670ee9b11282c0f027e", 3593750 * COIN),
std::make_pair("4a253d827060e54f6c0c16f3ba0889ffe889eb60", 3593750 * COIN),
std::make_pair("3b640152b82fc7698a33047519a6d2ec3a8d9b27", 3593750 * COIN),
std::make_pair("63df9040ce0f16d7a1507c5ca42eb0eacb4b102d", 3593750 * COIN),
std::make_pair("47aeef0f0fc9d0932a514fc0784f7a34166643d3", 3593750 * COIN),
std::make_pair("27b46c1774db65481ede1e67ff047ad7b350ae3b", 3593750 * COIN),
std::make_pair("5af6f4203e2cca817dc8a060c9e6f5d6afed40dc", 3593750 * COIN),
std::make_pair("86d3d7a119f3366e1d61fe93aeee2b1741052085", 3593750 * COIN),

// together tomato slab concert hill foster grace mad feel bulk spell struggle scrub payment radio wrap glad ribbon recipe region reflect seven minute clever
std::make_pair("06c9934173b9e471e724d8948ab6e43f434f1d87", 3593750 * COIN),
std::make_pair("3175a0899fecdc04d540d872644968b87e341ea6", 3593750 * COIN),
std::make_pair("14a44c7f6f0381f1879297a604991a15d226d3d3", 3593750 * COIN),
std::make_pair("b7c8811f0eef04941ebd6e758798a6fb42b8931b", 3593750 * COIN),
std::make_pair("ab1897c1b1c2da8913e38bfae0c332a3bbbff54d", 3593750 * COIN),
std::make_pair("64d9bbb22119f5ddfb21e66408b000643e5e89bc", 3593750 * COIN),
std::make_pair("cb9fc2bcaf610acb68e6709be3f8d644d1fd7278", 3593750 * COIN),
std::make_pair("166964ded68aa35c318fdd24d53c198cfb12850d", 3593750 * COIN),
std::make_pair("aa8fe630730337e38b01bf576c7c65bc3f19ef9c", 3593750 * COIN),
std::make_pair("9e1c19927f09e238834e7b0ef81adc5e2d12dc98", 3593750 * COIN),
std::make_pair("af33f6fb89a5c99e878a1d3ada11be10828cebfc", 3593750 * COIN),
std::make_pair("9e1b8716b96eb470f7a8f8da0e0c04e1fdbbcd43", 3593750 * COIN),
std::make_pair("dc38206e6c152b7e6df8d220ffff71f2b3df1b01", 3593750 * COIN),
std::make_pair("ce2946721286ec802c2991e2b4ab72d315a7ac94", 3593750 * COIN),
std::make_pair("1785652f0f3aa1682432fd2d5124e272d9b24183", 3593750 * COIN),
std::make_pair("c79980604af1d19a48407bae8fc916f98060e1f3", 3593750 * COIN),

// raven region finger angry oppose cheap become involve rare chef zero trouble roof engage message census talent abuse derive zero prosper hill around song
std::make_pair("d07f88ef59a6aa37b33f8be133db6f19744dabfc", 3593750 * COIN),
std::make_pair("042c32a7e4b14a1f2428bca1c1db9b10f208ee69", 3593750 * COIN),
std::make_pair("14e5f8dd5a6c0939e33522aa68b1d42fdde900a8", 3593750 * COIN),
std::make_pair("45cde217612b6a0707c320486da68636fc78c349", 3593750 * COIN),
std::make_pair("284927e678362d6b3133aea7000376031f11a0ba", 3593750 * COIN),
std::make_pair("26e794838b0fc95db029047bf2b06ea3c2b11173", 3593750 * COIN),
std::make_pair("a0c3e2a2eb36341ffdc19c978304d676fca7e866", 3593750 * COIN),
std::make_pair("f5622e5c0da76849e2d7f22eed110d0e5f0e8379", 3593750 * COIN),
std::make_pair("4499c6ec9bbada6b5ef0becdfcda301674e4c698", 3593750 * COIN),
std::make_pair("99f701563b12bd805b121de226a25a3d22c3ce61", 3593750 * COIN),
std::make_pair("759e607c9b58a84d2f5c8115ab62e98c461d79c0", 3593750 * COIN),
std::make_pair("1d3748835b8a738ac8bd9b8876aed4d7ea825d0c", 3593750 * COIN),
std::make_pair("063d2bf03a2764a289e83c726d48350949a8e130", 3593750 * COIN),
std::make_pair("c5f23e020b139442929b6d67ccce21d137b4da46", 3593750 * COIN),
std::make_pair("c2966e6144a31d4d7d01f2398bbea1c32cfa25ef", 3593750 * COIN),
std::make_pair("f0677f6548b90db0919590e092a276f896c67e1b", 3593750 * COIN),

// visit smoke bless gasp idle shallow theory chair motor hold arrest wage when crane remove theory mirror minute bulk hedgehog success hover harbor judge
std::make_pair("a1e3209e2d36baa6c32e27b614a32d69094d0a88", 3593750 * COIN),
std::make_pair("87e043080304c7fdf114faa1867b5b817e10908a", 3593750 * COIN),
std::make_pair("0d3f4e22d36f327f566c270157e8a560c5c5a5ef", 3593750 * COIN),
std::make_pair("d75ae948b8967f49f7aba12be78aa9c48b48c0da", 3593750 * COIN),
std::make_pair("f25f03ebaa72a6b88ac6962947bddd1edf110c43", 3593750 * COIN),
std::make_pair("56f33ff83b5c6939b2e80cfbc655584fbca4266a", 3593750 * COIN),
std::make_pair("0cfb00adf23a89ab4691897d9535303e2d9d8771", 3593750 * COIN),
std::make_pair("c21aa15a107b77fba9c14d45ba26ebe0a5133be4", 3593750 * COIN),
std::make_pair("b403020961b900b0601f934477196f3765cddc2b", 3593750 * COIN),
std::make_pair("0a0535a92a31101914c21551a83bec744ed9ce4e", 3593750 * COIN),
std::make_pair("f69e289c0bc2d3fa5b8735239cc9956679b0f0ce", 3593750 * COIN),
std::make_pair("ae6173338a58b3690c07994eeeafc5064bd1e1b5", 3593750 * COIN),
std::make_pair("f72d9919337bff84aae14b25fb995920d72aff16", 3593750 * COIN),
std::make_pair("ab3351321cdcdaab1dfbcdae2919982ba97dbe99", 3593750 * COIN),
std::make_pair("2ffd5e3f92c3fe8924f7857778398d69948f321c", 3593750 * COIN),
std::make_pair("be335965f1961ba024a8bc4816151a59014f7abb", 3593750 * COIN),

// defy romance aware public essay inherit sorry warm payment syrup rally suit payment shiver census slab thought scorpion verb left marriage guitar final sport
std::make_pair("fbda8bc60a80aef9356d64394e4e296d36ef59ef", 3593750 * COIN),
std::make_pair("953a9feb805f389ceb4d7e547846b819a2eb0e22", 3593750 * COIN),
std::make_pair("dc4d8fa9e8ab98ed5074847f62e9e3abb98e51ca", 3593750 * COIN),
std::make_pair("4abb0e6766549f3e32f35a5d3fd22e5ea13d73d8", 3593750 * COIN),
std::make_pair("f0feb840d4c449b80138977bd40b84b6ec3dda0b", 3593750 * COIN),
std::make_pair("9af4e24ceb73232063e821f47e3b11b57e01358b", 3593750 * COIN),
std::make_pair("9ee19426a70648574245e24f8dd50264f25e119e", 3593750 * COIN),
std::make_pair("0a922e84c595af00cad6a4355a9a7ce53649333f", 3593750 * COIN),
std::make_pair("bd1f700a987a43ae57ef65ecbdd7e643ad4bae28", 3593750 * COIN),
std::make_pair("ea0f7531136ae529030f64e309ef5e4b9d7374f8", 3593750 * COIN),
std::make_pair("0ec64feb48cfee0c83c4891bc4416c462d865be7", 3593750 * COIN),
std::make_pair("ad22ecf594d49674868cc90c00a0ceb4ad638007", 3593750 * COIN),
std::make_pair("bf38236e369a09a83d3653c572e65ffeb8182db4", 3593750 * COIN),
std::make_pair("f7c0e92da0e4aa729f319595b6aa2334e9290a47", 3593750 * COIN),
std::make_pair("f1b97091f9d5be43ec4356de8e661354b98877cd", 3593750 * COIN),
std::make_pair("0f53a52910e8176c085dd4926f924d0adde4f79f", 3593750 * COIN),

// attitude gadget adapt spring spray poverty protect neither snake border myth wall author supply joy estate family symptom fever wall parrot tooth athlete display
std::make_pair("73c260c63b2896d297ce3f5e562f0468453fc82a", 3593750 * COIN),
std::make_pair("a1e6e38f04b48e0b98b4cf6dc81231b1eb56880e", 3593750 * COIN),
std::make_pair("7802ff413251f57c79d33d5946c551b079161ae0", 3593750 * COIN),
std::make_pair("1471e4adeadb7580e4cc037a710bdc29d32f98c8", 3593750 * COIN),
std::make_pair("dc552450b16873cc35ba1ebbfbe615f43d6a8c83", 3593750 * COIN),
std::make_pair("059150947f293a650c57acc032622575770d9125", 3593750 * COIN),
std::make_pair("c398c10d26d18f63db1edf64e833ae70be14b0c7", 3593750 * COIN),
std::make_pair("281b584a9034f78614ccefda81f4ce0daf984809", 3593750 * COIN),
std::make_pair("15f47537aeb43578bda351db676782de605a729a", 3593750 * COIN),
std::make_pair("f05b707a75ca6975d5abc3b11f81b19f7c6574cb", 3593750 * COIN),
std::make_pair("d9f750f1984da5519d13e4450c9744f53569ed89", 3593750 * COIN),
std::make_pair("f4daa2b5c4eaa413167ffb4cb97f8b6749d97e68", 3593750 * COIN),
std::make_pair("b2dc967f32898491bf69a774789dbfc0b39f533d", 3593750 * COIN),
std::make_pair("c8bbffda28e59e25630348459b6c46d8a8e51ca0", 3593750 * COIN),
std::make_pair("c9d95ca38d6681f0fafa19f954c0cbbd779fca9a", 3593750 * COIN),
std::make_pair("9bb84d3f88f5ae39a94076178d513ada525b4434", 3593750 * COIN),

// couple inform together win extra plug room silent silent climb pass original moment canoe acoustic dance lunar shield jacket number blur fossil crisp slush
std::make_pair("7b9b3a20afe1847f4235d98db9911b7b968ec1d0", 3593750 * COIN),
std::make_pair("558eff36c1e2f6ea1c121ece93461038ab27c4ca", 3593750 * COIN),
std::make_pair("2b0868a0b768482b8d042254a8056f45ba665b9a", 3593750 * COIN),
std::make_pair("2c35c6941a45c1b7f1704b0a1fdd3cbc576ca260", 3593750 * COIN),
std::make_pair("91afed2da87043fbd1b680519e4c66a2eca19b30", 3593750 * COIN),
std::make_pair("7010fe6ee31ef3babb07025467a26573ed6bb9f8", 3593750 * COIN),
std::make_pair("f9b35023dcfe9750c3ae19149b5464053a5e4809", 3593750 * COIN),
std::make_pair("0b459f6b88c7eb961a1d16d8e41f15a7ced46ce0", 3593750 * COIN),
std::make_pair("611cb4c0680420451b34b08079f749266c94bcfd", 3593750 * COIN),
std::make_pair("ed75624c7d2d41bc000580c3bcdcaf63a5cb2a49", 3593750 * COIN),
std::make_pair("93a293a1b03973b71f6722070b57a3510ae22f10", 3593750 * COIN),
std::make_pair("a57d705994f2a9674dfee21e758a8b8868db1971", 3593750 * COIN),
std::make_pair("297e22edee7f2610d115c82f624ea4fbe73458da", 3593750 * COIN),
std::make_pair("48e8acb93c2c9deadb530d782ff4a801928610c9", 3593750 * COIN),
std::make_pair("ec1d1de2038c373952367934cb44be38e255c190", 3593750 * COIN),
std::make_pair("0b77bddac229a34d0f146812841aadec1f1792db", 3593750 * COIN),

// leg tiny virtual test casino soup flee deposit inspire stamp style rib earth hybrid teach draw raise wagon smoke marine limb banana sick winner
std::make_pair("01e8d5fa7d4edbb2c1130930b80489bbcb3f53d9", 3593750 * COIN),
std::make_pair("ad0f7c143ce9fb6914a645628c7d805f26ced920", 3593750 * COIN),
std::make_pair("f76f0f555ce02455f7f44a8e08d8bc40892cb252", 3593750 * COIN),
std::make_pair("638ecc2fca738cf6f04e0274c62e20bbb35db0fc", 3593750 * COIN),
std::make_pair("a43200298d995e1dbc150e21102a4311f6334674", 3593750 * COIN),
std::make_pair("1b43bd19b4a39e7fa0a22f0a659b50b8dbe4bea3", 3593750 * COIN),
std::make_pair("f0913a8e318b539b3b33614a2d9022dac4487037", 3593750 * COIN),
std::make_pair("3b579fa4327d74c1b2f4d7136e969240ac3fb531", 3593750 * COIN),
std::make_pair("7749ae0919fb3a947456499e14d64484986f2261", 3593750 * COIN),
std::make_pair("27ab5f3b8b0b5007b3345d4f33072c26c1c2e768", 3593750 * COIN),
std::make_pair("0ed6b86500fec4db16fefb6552aaa1716086583a", 3593750 * COIN),
std::make_pair("3cdafe2d1818278795cc8868d5afa71a1f242b0e", 3593750 * COIN),
std::make_pair("2163f0685c98dcdbc4554f6a15b6d2d975687753", 3593750 * COIN),
std::make_pair("e290a6fe6d1853eaf3e36ee50dcaa9a7f0ce08fa", 3593750 * COIN),
std::make_pair("fa88ca29a4ecccc0fee9e76640564f0637951505", 3593750 * COIN),
std::make_pair("4c6b9a9f6925aaad138877d4839ff4713881ef58", 3593750 * COIN),

// will inmate verb near open rural shy hover acquire daring riot soon pulp razor sport plate nuclear crime tilt will mixed girl van arrow
std::make_pair("21fd8f1e7f55263154a192a7f0807872e564102b", 3593750 * COIN),
std::make_pair("5c05358b112e7f6ec52ef78f364c091b45e5e37b", 3593750 * COIN),
std::make_pair("e32f7d48a616e2d8d15b106570b55e8f8df2c335", 3593750 * COIN),
std::make_pair("354ac828a43b2dcff04a92fdbbd9189f3d9d5017", 3593750 * COIN),
std::make_pair("42d6a62126313385f87015bc881c69c21e45e4d4", 3593750 * COIN),
std::make_pair("339f12ad73db9f068ac0001ae587b9f6d2ee4417", 3593750 * COIN),
std::make_pair("78aacf8fecece0713f690e4c5483a3ff38bcd02e", 3593750 * COIN),
std::make_pair("86abac7fd062ad06ea5f0ff6a74eb565fce68a68", 3593750 * COIN),
std::make_pair("f5c109014c84a6b6a7f924c4c01c579f60f6e040", 3593750 * COIN),
std::make_pair("2c3dc475c88ee01b44279f9b4c9fb433768d4fd2", 3593750 * COIN),
std::make_pair("8363d381f0461f6949a08314c36878568b8a1a1b", 3593750 * COIN),
std::make_pair("824e196bbdd4b87ffc0afc5fe5b478d45e56fdb6", 3593750 * COIN),
std::make_pair("a27c8f44897f143fe19846978ed0c9a4de93b3c7", 3593750 * COIN),
std::make_pair("5be83c9f1bee0f86e582d80e8ee44592c70df022", 3593750 * COIN),
std::make_pair("e485a4fc89437355a180a4051b943fe8bee26df5", 3593750 * COIN),
std::make_pair("3976d0e47daa464df4a64b4dc91752db23753e32", 3593750 * COIN),

// palm bless hair reveal once cart still final match gesture mix empty hard focus engage little enough december bulk crawl junk summer fox pink
std::make_pair("b0ae90f955516dde216c8e80e866d49445bd823a", 3593750 * COIN),
std::make_pair("bbb9ab6f83ab818af5c565713072f233d75c62aa", 3593750 * COIN),
std::make_pair("10e5c66a7983851bdb19499363fdd21ac518f1af", 3593750 * COIN),
std::make_pair("56a08908957f088cb140c451c15498ad9f887394", 3593750 * COIN),
std::make_pair("475aeb016cd4f55fec3b4f141b94fd819410b338", 3593750 * COIN),
std::make_pair("f07ab075eb2472a97ae2bbfc79a101d879f6eb52", 3593750 * COIN),
std::make_pair("6a1a3f0f0b4420ea6c14f18fdaad74947f889f9d", 3593750 * COIN),
std::make_pair("c2d23716644b7c799f1a50e8c9f7717196b3f5e8", 3593750 * COIN),
std::make_pair("e3435d2ee9a9a22b81395469633cc96f766a150e", 3593750 * COIN),
std::make_pair("19867c6252a914c55c1529f7efcf057385f0725d", 3593750 * COIN),
std::make_pair("e3162eaa3db8f4435319cc9bdbc4623c59714306", 3593750 * COIN),
std::make_pair("62c95cad90af91bdeac00deff151454ba4c22202", 3593750 * COIN),
std::make_pair("889a7ebf8d3c4b4f011793235641652fc98cae7b", 3593750 * COIN),
std::make_pair("171b10b24b13a5b10428be93212a31240a7b0e78", 3593750 * COIN),
std::make_pair("709d3cdd721f77016e9eca971153c769bd2aafed", 3593750 * COIN),
std::make_pair("3a54452fdbb4022b7ca7121f8c1bf56be01bccfa", 3593750 * COIN),

// useless dial sport limit federal margin outdoor art anchor subway advance autumn poet patrol ethics tent recipe phrase grace memory faculty sphere lizard capable
std::make_pair("d2b671a737140825099e158e746a2c26cb25a5f7", 3593750 * COIN),
std::make_pair("7094086fb107cf211b01eed281cf6f613341d946", 3593750 * COIN),
std::make_pair("8acc7743abf0a035fb71d04086fbac8cebb2da41", 3593750 * COIN),
std::make_pair("bc3e4f2124a1e2db1307769364a7a4350048ed65", 3593750 * COIN),
std::make_pair("2ed450dec896e67ca15b17597c9960a3356634dd", 3593750 * COIN),
std::make_pair("d6c0b40ddba43b3b85a5d739e9a8145d9368bd32", 3593750 * COIN),
std::make_pair("0297577c82b8ad57791da27afadbeb68eda54761", 3593750 * COIN),
std::make_pair("763504bef8b7d34f933fd102973798ba1e1185a7", 3593750 * COIN),
std::make_pair("deea4c2f60bbb5d2078e905c0cbb831ee0e5bd7a", 3593750 * COIN),
std::make_pair("e33553dc1dfcb39eba42726e91ecea33422c463d", 3593750 * COIN),
std::make_pair("d864d2154a0016a276768fd804723d9459f2bf8d", 3593750 * COIN),
std::make_pair("c03639fda6da9b7d9d79d79fce88716becbc615d", 3593750 * COIN),
std::make_pair("77bada3cbcdf60999cf46e8432f7e89ad7226afa", 3593750 * COIN),
std::make_pair("ef94ba41f4f8cf9df3a02b6187e422320757a4ab", 3593750 * COIN),
std::make_pair("071964f930af72040b8b97802d93ec021d1de991", 3593750 * COIN),
std::make_pair("768861019dd00cf43fe795c869130f6af5e01a74", 3593750 * COIN),

// film trumpet rare tone group pass flip happy guilt civil december hungry pill shoe buzz fossil dirt goddess change shoe proof struggle audit auction
std::make_pair("593662eea87cf50133344e72909e58d823aca9d8", 3593750 * COIN),
std::make_pair("853d934709b55ded8e6396237fb8d200a13ea130", 3593750 * COIN),
std::make_pair("8b0c448b03ae2578a847d060660a389ebc8c4e27", 3593750 * COIN),
std::make_pair("fdd883b24382a976c9c324c7fb40d910ef00dba0", 3593750 * COIN),
std::make_pair("d193d8db73b1a35fac62d692823bcb34f234247d", 3593750 * COIN),
std::make_pair("d2e9caf36d0813399296aa97b42b054165465e86", 3593750 * COIN),
std::make_pair("91a650c179c9d97b43e9855e5940ee98dfc26775", 3593750 * COIN),
std::make_pair("7123d335c5254af80a1edb6f5b47d5daa2985aed", 3593750 * COIN),
std::make_pair("dd3fe3caf227a394df6e8458b17d76bf318f96b4", 3593750 * COIN),
std::make_pair("2e0c4bc81ded8737d9c0724e2dab246b7107eaa6", 3593750 * COIN),
std::make_pair("dcffb6ba7da60a122d230a7d8e60af804975c259", 3593750 * COIN),
std::make_pair("9c0b452c5f2790492e39b8f99e42176e1dd134da", 3593750 * COIN),
std::make_pair("40856508c93028804df5cb582f3a217eedc293f4", 3593750 * COIN),
std::make_pair("eb64698fe129aa0015c1065db75c5ae739278499", 3593750 * COIN),
std::make_pair("eb18e3853c5119e0f1b09da5f158dd9e53b57c10", 3593750 * COIN),
std::make_pair("899570e4346733d0760fd00d5a83f2c8cb4460c2", 3593750 * COIN),

// sister blanket nominee metal enact dutch despair easily material own chaos method venture snake clown walk derive limit able kid broken expect mammal bicycle
std::make_pair("02f522936e1a6f24de863a75c8fda4c83c53ef75", 3593750 * COIN),
std::make_pair("3abfb5a187aba24b0ba81ade981ddea80e57e7fe", 3593750 * COIN),
std::make_pair("44ab7a6b912207904240bc15b92c56dd83e1fdbc", 3593750 * COIN),
std::make_pair("79dc297ba321a9583cccc128ed8b32cce8d3e007", 3593750 * COIN),
std::make_pair("beaa5ecdd8c8d7c87a6cc03e43a741cdf05fe338", 3593750 * COIN),
std::make_pair("d2a81c903a3a2d9505ef6dc6304ae15bb1ee23d9", 3593750 * COIN),
std::make_pair("6212f7bb4383dbce21150b8ca4ecb59f2aba729a", 3593750 * COIN),
std::make_pair("e86d20c41d98e7d6b532c323abb1da8e77467b51", 3593750 * COIN),
std::make_pair("bd9621d3b2a3d8bc06a9dcc04a3d982596d4040b", 3593750 * COIN),
std::make_pair("d24c466df8084f1a48aacc4aea3546b50cc95608", 3593750 * COIN),
std::make_pair("b5a03c747fe2d8ea4d97105544c8279f28ed27b1", 3593750 * COIN),
std::make_pair("567d2033245fa5bb31833a7f03c00d5e32860280", 3593750 * COIN),
std::make_pair("ee54617df1a8438db4ae77497fe749eb141cb0bb", 3593750 * COIN),
std::make_pair("7e072c7d6609f9214fa7168d6541c7bbe0952893", 3593750 * COIN),
std::make_pair("a37a9067a0694b9714a7b9b66f90706780dc8a73", 3593750 * COIN),
std::make_pair("bea7c5bbcd93eea8314ea47186fc3697ab7a16fc", 3593750 * COIN),

// depend border lock small hedgehog obtain lottery regret furnace good brown bag cancel phrase hospital breeze force love earn capable original hamster steak web
std::make_pair("b1df544b4f0ceb6265e478bb52e9a1d36b9e66f3", 3593750 * COIN),
std::make_pair("23e6d193d15007836f62898e7756da894cc45c9b", 3593750 * COIN),
std::make_pair("5d8363a1a504e24c68cc9f6ffddddcf3bc39e44f", 3593750 * COIN),
std::make_pair("e71fe88a11fdf81404f7411d57bfb1ef43996482", 3593750 * COIN),
std::make_pair("b5061f2d760e36c2e551f75e72beb3c2cb2d1e9b", 3593750 * COIN),
std::make_pair("39fd03bb9b62e01027b4ffe4de066f7dd0f5c50e", 3593750 * COIN),
std::make_pair("e05c16745a94882cff2bed7b934457a0855ba5aa", 3593750 * COIN),
std::make_pair("1e763a4aee4cd880a3dc47f411787d0f0dc83dce", 3593750 * COIN),
std::make_pair("43e522cac695d59d895bd2460061c0e02623fb00", 3593750 * COIN),
std::make_pair("8deb35bddc785353e8e17d4553c0c16dc65c8a02", 3593750 * COIN),
std::make_pair("5088beaac6ede774c628ae507883a3ccbbddd3a5", 3593750 * COIN),
std::make_pair("764461f2953a62fe8a743e25de30d2d7a8f26423", 3593750 * COIN),
std::make_pair("c1dc33f285ddc06e923b12e8acac42b43c8f15c4", 3593750 * COIN),
std::make_pair("b0e8aa0198ef85a58ee8c9315950ff71ea210dfe", 3593750 * COIN),
std::make_pair("71bebe77036db3d0bb04503496ecb9e7589416c6", 3593750 * COIN),
std::make_pair("cdbcc0c932422155191629d30cfe59ead1e97e77", 3593750 * COIN),

// diamond flavor tuna whisper gas fox tool casino whip sausage turn satisfy suffer fluid town deposit forum decide sting taste slight inquiry view biology
std::make_pair("e339297c6f70d8cb5ddf93a8e77b2afb55af5b98", 3593750 * COIN),
std::make_pair("87c96a6a7d3f083616fef83c3506be985de2c943", 3593750 * COIN),
std::make_pair("70d1a47736ef8afd6c6d81ca5b43e3e61314e1ad", 3593750 * COIN),
std::make_pair("32ee6062caf19d538d8faaa5017c1b8ebb76ac63", 3593750 * COIN),
std::make_pair("2c02edb6bd17035ca7970af9daa5badb78615471", 3593750 * COIN),
std::make_pair("464de288e2d7063bd7f75ad4b7a2597775103dbf", 3593750 * COIN),
std::make_pair("a0e8e421e060667b42a677e2d83a0b73a3ccb2dc", 3593750 * COIN),
std::make_pair("1cf15ed2f887e068b51764d26e1939491b91a5de", 3593750 * COIN),
std::make_pair("dda7e09819c5ceb0a9550310b5587b1731d12c3c", 3593750 * COIN),
std::make_pair("ab711abf1e1571a1d4b183b6296f4969fc5b45c2", 3593750 * COIN),
std::make_pair("f8c1435e3726bedbbf59eff5e9a4a0896992ffb4", 3593750 * COIN),
std::make_pair("c4bca2bb187a2fda7ccd597fe0f27f9eaf08d138", 3593750 * COIN),
std::make_pair("abc5142ea54993f0a1d73227a8394e776a777327", 3593750 * COIN),
std::make_pair("dec1d659e24c71b1c79442d82199621c12681049", 3593750 * COIN),
std::make_pair("c4072bc7c0e6915478b2419d926211c3543871e8", 3593750 * COIN),
std::make_pair("e5e49207796126b8912a3ddd6cd9453fa2582036", 3593750 * COIN),

// shiver budget party wine rain syrup ball violin trumpet pupil gorilla before space screen fork chuckle memory lawn shine humble stumble kitchen draft friend
std::make_pair("12e8e9f67ffb70d0f57e90403ebd2817e53ee4d6", 3593750 * COIN),
std::make_pair("b8f82f2e34d7235b118100647de7637def0655b6", 3593750 * COIN),
std::make_pair("40dd21d32156b4c62ad536135ef82b890029fc01", 3593750 * COIN),
std::make_pair("18ad3290da74229620e2cd5298db0350841ec3c9", 3593750 * COIN),
std::make_pair("d48ebd56a37de0c8a10284691825e31887294287", 3593750 * COIN),
std::make_pair("0cde417b09df2058323b420c4213f7d4ce6f57e7", 3593750 * COIN),
std::make_pair("83c56c2a2057f413ac009637d830510eb3a3956a", 3593750 * COIN),
std::make_pair("b4fc9bc3d7bdb68486e2c7ff099c26db78345edc", 3593750 * COIN),
std::make_pair("56c0daf561125e895c3fe0ab7dd8f4ce33037e2e", 3593750 * COIN),
std::make_pair("662185141319466ea602298c6b04b82a50d96228", 3593750 * COIN),
std::make_pair("e5d64483de5b2e36609999b03fe0be692bc1531b", 3593750 * COIN),
std::make_pair("11786bde76e4686f4e63dbba21b5d8dddc4d08c6", 3593750 * COIN),
std::make_pair("afe0bed58b82fc58e4f0f7c3c344749cd8b00d2f", 3593750 * COIN),
std::make_pair("97d0a36acd61edfc6dd488c0e6f6d6b345bd2b5e", 3593750 * COIN),
std::make_pair("72a9db27d613dbcd79c2ca3f3306682401fca930", 3593750 * COIN),
std::make_pair("d5799c4d4122dafcf51da253ef77a56579d29ecb", 3593750 * COIN),

// double knock scrub alone struggle range later seat pioneer answer wait daughter lucky photo old embody hurdle bachelor awful spoil corn iron arch always
std::make_pair("4d3b807dd9910de31f54f07fa23df4ddbf3748e1", 3593750 * COIN),
std::make_pair("e2e07b4135d6d38bd6ba20329554d44412fb34a3", 3593750 * COIN),
std::make_pair("c578029a96a42b157b561dd2185c0391688f7153", 3593750 * COIN),
std::make_pair("e37cea1aaa0056f91ed37225d58d891ea0275179", 3593750 * COIN),
std::make_pair("2a9ff8d510044a7066d88586156ce39ecd3025c3", 3593750 * COIN),
std::make_pair("e52b65bc7a63586509cf5a86b1a5462676bc7373", 3593750 * COIN),
std::make_pair("f0f3086e32244f02b96ee68703c67b8e1d00dbd2", 3593750 * COIN),
std::make_pair("056af2c20cc7e4ce404e25b7e7026cfbabaa2874", 3593750 * COIN),
std::make_pair("ce3e9d8a4b6f4430124d858b5bc54c6e5711a914", 3593750 * COIN),
std::make_pair("5f5505f3ab4b4db9902e1aabd31fce306fa0eb76", 3593750 * COIN),
std::make_pair("2851127866a6af5ac80a0d1dd1c1a9e3dc6fb572", 3593750 * COIN),
std::make_pair("9363e513c124addac5cec1dd51bf436d84dfeb9f", 3593750 * COIN),
std::make_pair("a2d4b33cc20e7c119ab11bfeb25143ca4f4755c5", 3593750 * COIN),
std::make_pair("41fc23fec03cc1f8e305faad10e6963b40427ff9", 3593750 * COIN),
std::make_pair("12d248c8c1fb5c278424886fbbbec7ed3fc00d43", 3593750 * COIN),
std::make_pair("3f8203b30185c41d91806186fdbc368f324b8c30", 3593750 * COIN),

// fatal stage tide fog uncle walnut various foil fluid move machine company family spatial proof half crew betray addict insect kick hawk sword believe
std::make_pair("7792184ef7fba95f587dc407444e22237e3d7679", 3593750 * COIN),
std::make_pair("82a61e3dfb704d6d224925e0152c26567a7401bc", 3593750 * COIN),
std::make_pair("d007e4bb8f36230d69aacdb8405b783bdfe1c92e", 3593750 * COIN),
std::make_pair("fcbe445a74178c8bcd7509c04c0ae831547d164d", 3593750 * COIN),
std::make_pair("d7fd88b7cd4ec7e70872ca3f32825a37a774c9bc", 3593750 * COIN),
std::make_pair("caabe37dd5e8b57e44c8e593b5c5de2fa8724366", 3593750 * COIN),
std::make_pair("9051b6396cf707d06a15d91481dea4cd9f9e8062", 3593750 * COIN),
std::make_pair("9a8fad4df17f2592926d73acf07835e86bb5552c", 3593750 * COIN),
std::make_pair("00b223789e8d612f35b474bd291a55906b3591de", 3593750 * COIN),
std::make_pair("f19c07ac67d930429e0bad121238774f6aaaee4d", 3593750 * COIN),
std::make_pair("20a10916497bb919d7a925dbfdbe3edb25e7b6a3", 3593750 * COIN),
std::make_pair("e460f4da99c1f3c69796a5d192fbbdb56561bcc9", 3593750 * COIN),
std::make_pair("a61d25fa258eb4de33ce1627288be5ec0d5f41ee", 3593750 * COIN),
std::make_pair("aea9ebb842a9fe13f62df39e7e3dc14151eed35d", 3593750 * COIN),
std::make_pair("ae9f502e552b17bc9b2bdd5a537155d4ec118a5b", 3593750 * COIN),
std::make_pair("e224059c4854f37200c8b8d12d1696923b428597", 3593750 * COIN),

// romance gospel frozen soap elbow famous pear stage inmate coral crash chase struggle direct tape remain ignore local flavor edit tonight coral crack snack
std::make_pair("a65727ef5e69053382f4a8cf15b37901f8083af2", 3593750 * COIN),
std::make_pair("9aab685c2fea1e0f2d348f6b650658d7846cc60c", 3593750 * COIN),
std::make_pair("6e31a5f90ce7059af97b1b70f9b0302fb73957ff", 3593750 * COIN),
std::make_pair("0723ae9e780757a8367f407d1fbe8a83284fc64b", 3593750 * COIN),
std::make_pair("45606218749510febfa3e87b46a6ebc6a50a60f6", 3593750 * COIN),
std::make_pair("f5ebc1129f83ed3956ac2ed72c7dcaa5249b7128", 3593750 * COIN),
std::make_pair("a81e1188f2bb64fffeca55050c49e17925a5ee7d", 3593750 * COIN),
std::make_pair("8eee439509e5b67c676f12344d11811301c14a95", 3593750 * COIN),
std::make_pair("c451db47d6121f7488535c201762d3e469b93fa5", 3593750 * COIN),
std::make_pair("fab56531da60daa213ba39812e3e30cb608882b0", 3593750 * COIN),
std::make_pair("19303acf6af36ab8cdc243e06c86cf611037060c", 3593750 * COIN),
std::make_pair("5b50c53ffb5ee55eb5e6b8b83cabb75a29ad9783", 3593750 * COIN),
std::make_pair("91e4ac9a4eab3b8755a528b0baaad487f06b6a37", 3593750 * COIN),
std::make_pair("534393e0e226102bd99c9d69ab7416212e94b955", 3593750 * COIN),
std::make_pair("fd56eacad98d7d50450aed96d96ba8326e075b60", 3593750 * COIN),
std::make_pair("b1d2a35182ebfb2e2b60f2b6c7618b18ff8e3a9c", 3593750 * COIN),

// album kite pulse chalk insect lucky song ketchup excuse wise fantasy sibling pigeon ill apart dentist boat sentence poet tribe uphold monkey anxiety leaf
std::make_pair("9ea2801ba04b42ef09ea50f8ca59390cf42c7a76", 3593750 * COIN),
std::make_pair("02c2bd7f30a549dfbd8182d4c5157acfcf28d5c1", 3593750 * COIN),
std::make_pair("8407913c90249808196d753fcbfb4871d2508777", 3593750 * COIN),
std::make_pair("8e7e3457cbe5aa4d9edf1fb5d97b1b157cabbd06", 3593750 * COIN),
std::make_pair("4fca5a4fa956c4edc333d23aa4d33ffb9c1452dd", 3593750 * COIN),
std::make_pair("2665cdd3c00a3f976421a2e05145a5f5d4fdeefe", 3593750 * COIN),
std::make_pair("1fff92e310c2fcfb7f42b7bd22b35815206cd53f", 3593750 * COIN),
std::make_pair("f1fbaf101ed788d0172f866cf854b5b3d44c0163", 3593750 * COIN),
std::make_pair("91efd6456a9a26370c02f18292ad20fdda69d447", 3593750 * COIN),
std::make_pair("3cef5d998b9a9dc5517da433923b3980d272e169", 3593750 * COIN),
std::make_pair("78a1be0a41f482e958e4991ae56ff810515b2cfc", 3593750 * COIN),
std::make_pair("a96ab0b167c5a97bedeb879bcd98cb7c8225ce71", 3593750 * COIN),
std::make_pair("f3a39b043c57518068abcca1bad68d6af581cd94", 3593750 * COIN),
std::make_pair("233ec3cfc0b5704d5dfd955b0e992da7d9e7c944", 3593750 * COIN),
std::make_pair("9cdb03c00e903503c11ebc8e251b0147058301ab", 3593750 * COIN),
std::make_pair("dcf13d9fabde4af7b542571bbe6f8390e73bd1e4", 3593750 * COIN),

// illegal tongue wrap future history spice wing hen panther try trick rifle ripple depart more refuse document angle enemy pipe return night build total
std::make_pair("516bb11b37a8f18272b2f16bb8e998f83b3d8ff7", 3593750 * COIN),
std::make_pair("b612da6e192f521a2b61dcdc01f317f6cfb96bba", 3593750 * COIN),
std::make_pair("f41a59a1966a9bc2c7c5861c00640f0d76d03c50", 3593750 * COIN),
std::make_pair("c1e5bf9b1b4186d44a872122d13b5ecb51a481c6", 3593750 * COIN),
std::make_pair("83755cf169160149ecc119a1ebcd0651154f5896", 3593750 * COIN),
std::make_pair("fe70ce044633123434d02ffea5203bf23df01645", 3593750 * COIN),
std::make_pair("758a76c309d8324b944c6b11446d6342a37bfde3", 3593750 * COIN),
std::make_pair("c624d7235c1d37029a47353a6e9d203cf75be6f5", 3593750 * COIN),
std::make_pair("11190eb3092673b50d88ee24c22384ed081e8f43", 3593750 * COIN),
std::make_pair("31805849f6d9389890779dbc9a1ba8913845d531", 3593750 * COIN),
std::make_pair("20d995891a517101dd7285efa682c4d8211efc9b", 3593750 * COIN),
std::make_pair("f059978ac1b1f8168cf56755fd0216fee49ea0af", 3593750 * COIN),
std::make_pair("99789d4acfdde9231818a3f4b70c5ed4bca6d8f0", 3593750 * COIN),
std::make_pair("32ede590d423afda3ebd370c841764ffd0b44626", 3593750 * COIN),
std::make_pair("df2d8890029437bb89f5affebfcb4097f4f2feb5", 3593750 * COIN),
std::make_pair("5486e0ec03ee7eeedcb425525d9aec12a701d110", 3593750 * COIN),

// ahead dust game blame property mouse project foil crazy canoe tenant melody face cat decade fashion post bar submit frog truly cost track uncle
std::make_pair("c3980fd65b9ce9dc9cbb516cd8ba04f403f1f005", 3593750 * COIN),
std::make_pair("765b408d06fd651c741addf8e8a1febcf3c53562", 3593750 * COIN),
std::make_pair("f66d17dc06a75a0a3dd3ec5842b77f07cfb63a50", 3593750 * COIN),
std::make_pair("2a877d78c077730275f1f38a0a91b29cc19d65a5", 3593750 * COIN),
std::make_pair("e6e5dba87c32bd5f16e09f3fe4f06276f67af5d0", 3593750 * COIN),
std::make_pair("dba56fa46dcc973064ec0d5e8ac82e4cae79f04e", 3593750 * COIN),
std::make_pair("4819ed328e28dcc6e0ceb3e61be86532213df655", 3593750 * COIN),
std::make_pair("19a2d75f75d9b88365ff4886f7a70ecf1a683ba1", 3593750 * COIN),
std::make_pair("2665ffa2b59cdee58a8f7177e748e119da5bc52e", 3593750 * COIN),
std::make_pair("42b696d9cfa52027429120de77f9009fc0bda4d9", 3593750 * COIN),
std::make_pair("3c590f44e147771843f7935ae6428450d9f75041", 3593750 * COIN),
std::make_pair("dd01fe8f51872069d9d6e2e7e8a01649b4e4e2cb", 3593750 * COIN),
std::make_pair("2711a30cc6035a7affa5f83630ce22d3206c6fa5", 3593750 * COIN),
std::make_pair("866d7583083c08a1c9c8f5a6dd1da601118c52a6", 3593750 * COIN),
std::make_pair("8ec88493fb3fe33fb998b71eacec90e538e2e2f8", 3593750 * COIN),
std::make_pair("5bcaef18548d872462c327e356bcde7c5bad2099", 3593750 * COIN),

// copper make ridge chicken unveil clinic trick say crush scene velvet virtual lumber usage crunch believe aerobic soon cloth pull grape veteran chair uphold
std::make_pair("967ec660ec9d4ddb6e57bd3c771f173f223a480e", 3593750 * COIN),
std::make_pair("35f18af39e54c2d297e164d6b88de9ffeda12978", 3593750 * COIN),
std::make_pair("5f5282e4e4b3a88d2bf067e07fab94df005a038c", 3593750 * COIN),
std::make_pair("e5bd65c01482ae007ac6e40b8428334676643e28", 3593750 * COIN),
std::make_pair("8707056263ee843b09c2d92d6d06ac6adb963a40", 3593750 * COIN),
std::make_pair("98f4ea53016056fb6d609f4448f8acb77fcd2e3b", 3593750 * COIN),
std::make_pair("1aee41562eebdaef50652b111dcfb878f6c2c059", 3593750 * COIN),
std::make_pair("237ff83c8ac55111d14fd6c83224304b13d9973f", 3593750 * COIN),
std::make_pair("d922a48eff85e70c3340683deae5ff7fb193f2af", 3593750 * COIN),
std::make_pair("7d56c3fe85def184b9caeec94b5e15429db4af57", 3593750 * COIN),
std::make_pair("77cb9ad9b57d626bc663d98bd017ebd7501b75ff", 3593750 * COIN),
std::make_pair("37e1ddf7831494e8cbf4512402b75781e328b169", 3593750 * COIN),
std::make_pair("9fc8a8352158ecbf7548b3b90f73c8e92336f43c", 3593750 * COIN),
std::make_pair("c41164393c56159a9a917c4696a01701254e3da7", 3593750 * COIN),
std::make_pair("568ed8012272bacda6164a90823f0df5c62772b4", 3593750 * COIN),
std::make_pair("16a6e981d81c00c84201c7930d66d8ad3ff13f00", 3593750 * COIN),

// oblige wall diamond noble purchase crouch awful bubble bless raven salute slow humor tube play example beauty camp bitter taxi humor mask man bunker
std::make_pair("791d4dc577c455024567687764961b17141160d9", 3593750 * COIN),
std::make_pair("7ecda8dfc13081c74071c7dfbd4395c510405aa3", 3593750 * COIN),
std::make_pair("1b06325c111717b509037e2950571d6664f87624", 3593750 * COIN),
std::make_pair("4414d30e303028451da032c90fac41455b201520", 3593750 * COIN),
std::make_pair("abb57c78f8c68f275483195da414035321f88055", 3593750 * COIN),
std::make_pair("fc4c97e94f7447e6467d322b9f9cf21bd7f34bf6", 3593750 * COIN),
std::make_pair("fc9fa41a1e077b0208db08b85941ccec4b88f8ae", 3593750 * COIN),
std::make_pair("305d101599cf343a089ea154d32be3e2e2aab0e3", 3593750 * COIN),
std::make_pair("ba7f224b5588e4ddae282add9a2351fef2e8b940", 3593750 * COIN),
std::make_pair("4c50b20247aecff220bd50adf11a38cbe0be9f5d", 3593750 * COIN),
std::make_pair("3461357c424ec0e3b0efbd0dc690dd5bfef242f8", 3593750 * COIN),
std::make_pair("e4842231079d97a748796d70e50b0c9860af7fe8", 3593750 * COIN),
std::make_pair("ff34e5d6510bf46dea568b8ff436ac22a91fac34", 3593750 * COIN),
std::make_pair("f409e8d449ae77563a1e70165ca4063a86daa510", 3593750 * COIN),
std::make_pair("667e1fa597b61596e8073d680a960ee3e4cd63eb", 3593750 * COIN),
std::make_pair("cfb1f1b6bf48dd48e2e1ffdbc71bfcfcdff2d2eb", 3593750 * COIN),

// wool antique budget leader blush clip bring birth awful inspire excuse civil involve curious siege inject dentist silent fringe lyrics solar stand file enemy
std::make_pair("c3d8f990d81f872148c47598f858fe946cbab017", 3593750 * COIN),
std::make_pair("aa66f98d07dccb35060298fd3efb8bf2ff1cde4b", 3593750 * COIN),
std::make_pair("0f5ec989e28e31101e204aa704a4b0983d18f150", 3593750 * COIN),
std::make_pair("78fcdc2ab0a11deed63bb0ce4af6a80ded3d3683", 3593750 * COIN),
std::make_pair("cb7c3b55a21d0ef106ce1e4d518e29af408a6b44", 3593750 * COIN),
std::make_pair("637985bfb8714aa3b268b64e5e23b1e614d7c445", 3593750 * COIN),
std::make_pair("1349557f76e56356a1a776bb02ba9bbc0285da4b", 3593750 * COIN),
std::make_pair("23398012d42f05e782044a29bf29eefb46b583ed", 3593750 * COIN),
std::make_pair("4eeafac7d87eb7391e5bd0abe2c5cb72241b1afb", 3593750 * COIN),
std::make_pair("7ba644569c35972d7625adaa2baa6aa61de2b61e", 3593750 * COIN),
std::make_pair("0de68b4f69a2eea59027aa53fe24eee751a8cf91", 3593750 * COIN),
std::make_pair("af2feb95a9816e34cf441ffad16f2352f1a500c8", 3593750 * COIN),
std::make_pair("354995c40fa6ff80d2c8c0bfe155dc163ea51999", 3593750 * COIN),
std::make_pair("05f2f6486abf96af31b12eaca31cb7d7892e3151", 3593750 * COIN),
std::make_pair("ba9bd0f9d16d8e0aa81025b4f55cb3764f037e1c", 3593750 * COIN),
std::make_pair("4dd04d1f515b9f338a9320403392821835a7e6b2", 3593750 * COIN),

// flight cactus cram country relief island notice husband apple amused slush happy squirrel amount chat armor quantum soft lottery jelly sign critic choose office
std::make_pair("8aa8bb2843a622ad7fe561f355499fe86cbe76a1", 3593750 * COIN),
std::make_pair("f7ef52580e8505ceb9b3ce2606cac0e00adbf82a", 3593750 * COIN),
std::make_pair("ba7d26f3d743b58041087ac5f2260fa228ebcc8b", 3593750 * COIN),
std::make_pair("c44b264c3ee6c69a63b8fec82d802e53c8076092", 3593750 * COIN),
std::make_pair("60c994cb812868a13d4863189faef139c2468398", 3593750 * COIN),
std::make_pair("4928921e885869bc99b8181701924d37af25265e", 3593750 * COIN),
std::make_pair("56b65c8af87fa15db9a0cfe2caed9e2af4be83d7", 3593750 * COIN),
std::make_pair("547ba1400ea724a625c7d92cc876d40dd5c5da5c", 3593750 * COIN),
std::make_pair("1a3ed650149dc1d3a65b87dac66063e958d3ba54", 3593750 * COIN),
std::make_pair("112ebef4ffdf10eebbd81e84831ff92688bb7622", 3593750 * COIN),
std::make_pair("eaf0f0aec24d7bf0548b5c4a20b2a7ecc6ad0600", 3593750 * COIN),
std::make_pair("6adc7c441ae538bbf01f51fc66da0db961e8964a", 3593750 * COIN),
std::make_pair("b7a13c9503c7993907a6d96840994269ed571219", 3593750 * COIN),
std::make_pair("4f7920fe856103a2bbd1e35280ccadbfc361486c", 3593750 * COIN),
std::make_pair("d79fc37a5fe3ae8e9f875b89a6f852d34531311a", 3593750 * COIN),
std::make_pair("2220bac24f2bda1c6bb5ca2e284524715013c658", 3593750 * COIN),

// shoot exact find vague pig crazy bicycle accident turn drive concert aspect jeans world best situate chuckle legend curious curious scene hollow host link
std::make_pair("e526be7b4ad756280e9e367a1b5c9f4f7036eb17", 3593750 * COIN),
std::make_pair("1c7a12cc5ef29b9cc899121fbe0ef03c65ee3a5c", 3593750 * COIN),
std::make_pair("c0d0835deecda78af6fa53f920b15b6cd1ba847f", 3593750 * COIN),
std::make_pair("1034c3e42b48d01b083cefa77f8fbacbd062e8e0", 3593750 * COIN),
std::make_pair("96251598e664b4eb13b2737456e7f0e268cf4429", 3593750 * COIN),
std::make_pair("5d46f3c301f6d4796e04b4b2fe8fcc252adfe9d2", 3593750 * COIN),
std::make_pair("58cf9f107495e223214cfc073c93f8559ab6c810", 3593750 * COIN),
std::make_pair("07794bc6e24c0cf5ddac830666273572766f52fa", 3593750 * COIN),
std::make_pair("a4b366975cbcf27b88eb2321757412a8d5f169b1", 3593750 * COIN),
std::make_pair("57df1a4994accbc34281a96c2fdef3976288291a", 3593750 * COIN),
std::make_pair("bef3bbcecf958f64ac98623b682c76bd3c7cd504", 3593750 * COIN),
std::make_pair("d3c7d904cddb1b274fa558487929d433b79f5a6e", 3593750 * COIN),
std::make_pair("82e52198751772144523d4a94e9e7e211f2416d7", 3593750 * COIN),
std::make_pair("70529a489f52ec6b51e97e57f8062373c41e1b7c", 3593750 * COIN),
std::make_pair("076d31a992badf317330794ff9ba61511d722ba4", 3593750 * COIN),
std::make_pair("f93829224bace0f4aef502c3de94aa618dca052d", 3593750 * COIN),

// notable best picnic jump slim museum kid witness setup success pair phrase submit broken quiz material coach odor fun theory shed sentence note oyster
std::make_pair("31b12dfe542d599f2c86173ef4e9f33070eb6806", 3593750 * COIN),
std::make_pair("f6b4567a7f52d0d1783d63fd803425d2367b7e48", 3593750 * COIN),
std::make_pair("cd83c119d71b18cbb4aa10ae3583fe2e0e1f6fe5", 3593750 * COIN),
std::make_pair("f549e4146da0ad5c5155959f3876a4ba41ec7925", 3593750 * COIN),
std::make_pair("3ae7211866b977569ad29841b7241493b083f0aa", 3593750 * COIN),
std::make_pair("70568088b7753629f35b682474f013d022b233a8", 3593750 * COIN),
std::make_pair("0c21dce58a5f8f5e4d5a123db1f40a9249f808eb", 3593750 * COIN),
std::make_pair("13f7c5bbbfe0ef80bb700ef76f45450b0a062b6f", 3593750 * COIN),
std::make_pair("51e2977750cc2b06f5aa068840ed33ef9a69e30c", 3593750 * COIN),
std::make_pair("01448439b55ecc95da9dbb48b0f415e756d6b0e7", 3593750 * COIN),
std::make_pair("270dcb323d41d16dfab4428e6c2ea542754e70bc", 3593750 * COIN),
std::make_pair("4ce5c871b110a9e6d6e2f591f88dbafd10f07bb7", 3593750 * COIN),
std::make_pair("23fff913eba18e6dff50a78c327a77a7b4c7d8f2", 3593750 * COIN),
std::make_pair("ed263ac430db8a81f4037b261b1b38c268899a65", 3593750 * COIN),
std::make_pair("be1f564434b4b6fe745bf8464a34284c1709a2e2", 3593750 * COIN),
std::make_pair("db51c0a35d604efa8907c1ba2bdcaf4f81091ee0", 3593750 * COIN),

// jealous ranch tribe army present hungry library push slow abstract alone sail riot close focus slice chaos scrap season sustain enable long final fold
std::make_pair("bace061508db57e4c327d22819aa7a7f20b36c50", 3593750 * COIN),
std::make_pair("90851bca65565037de859318902a611bc8da08cd", 3593750 * COIN),
std::make_pair("604e85e481c07bd1d34d943553800aa9d144176f", 3593750 * COIN),
std::make_pair("4424d56cebba02b1a09cbc3577b628c95ee1a5f9", 3593750 * COIN),
std::make_pair("2c9f184e1c6b0940e53a06e5023c419b1e55201f", 3593750 * COIN),
std::make_pair("26ba6cc2c303fed734ee24d87c2e270fa3f5f245", 3593750 * COIN),
std::make_pair("8a9c61c340d62fd18030a53514948954b1988510", 3593750 * COIN),
std::make_pair("490f748dcf6ddff41b3390206d1eb71677ebf728", 3593750 * COIN),
std::make_pair("2cc2c50a1d91d3bc4d5f35d35960b05f1e4d1fb0", 3593750 * COIN),
std::make_pair("777af33a4669db9b789d4c0675617c75b0a059fa", 3593750 * COIN),
std::make_pair("1d1cdbe7c90b6198bc7fe595bad86999798a9688", 3593750 * COIN),
std::make_pair("13133598ba0e46797c846931730213060d31f096", 3593750 * COIN),
std::make_pair("56ef7ad289adc9bc2e485a44f8dc6144763970eb", 3593750 * COIN),
std::make_pair("1c37ff0bfb703ff1fe23dd6f38efa6b4e655d8b0", 3593750 * COIN),
std::make_pair("816e28000c728b235b2fb0902496f109b5abce3d", 3593750 * COIN),
std::make_pair("d4c932c21835990c62055baedb1c8fbb22c6d363", 3593750 * COIN),

// inflict opinion ignore island soap equip worth trigger street curtain risk base ugly gesture ritual obvious owner six maple orient square already drama game
std::make_pair("f287c9fd4a5f22687ae30e1b2e9ab8f19c1b17a3", 3593750 * COIN),
std::make_pair("b1de66fa87ea4065d20ec591bb5a5a820ebea926", 3593750 * COIN),
std::make_pair("42392345d60604c2d530f791b052eab09d36325e", 3593750 * COIN),
std::make_pair("a4e898cf1aecc8339526b4dff68eb56b5d74bdca", 3593750 * COIN),
std::make_pair("6210f0f5e4177c94b7b2d7acac29531e70589849", 3593750 * COIN),
std::make_pair("a0aac7e19291f78f97029217b8e73f48ecb4f8ca", 3593750 * COIN),
std::make_pair("eaa7fb850d573a28a9a4bfeb95e0f494a320b719", 3593750 * COIN),
std::make_pair("442774a2be796437fc212139fcdf7c57bbee0f24", 3593750 * COIN),
std::make_pair("dd5abc55a5ecbf51c8c7c7dd901cdbffe84e6cbe", 3593750 * COIN),
std::make_pair("7c51f6eb59c143c3fd5f74932b0f8372c050c5fc", 3593750 * COIN),
std::make_pair("617be22d7d102519e29fc546892032f450ab523d", 3593750 * COIN),
std::make_pair("89ba6816f3da4846800feaa2f2dc77e70185bed6", 3593750 * COIN),
std::make_pair("f66215d4280b402ee9e38a9c9eed87470f513079", 3593750 * COIN),
std::make_pair("7fe2c4546031974e24848fa48217cd1c1fbe898d", 3593750 * COIN),
std::make_pair("521e2d46f3f14be56a7adacb356144b7dc7db975", 3593750 * COIN),
std::make_pair("686c058ed340a42d02e8d4c94e3563b3e4213144", 3593750 * COIN),

// toast horror machine quit kit west nasty goose faint frost spend bottom organ timber home nature aerobic camp ecology tower nasty border analyst coyote
std::make_pair("6555e736d37665bc5f11938a7e7eb9f53c7953c5", 3593750 * COIN),
std::make_pair("7fde4b96445e79019d0cd7ff79c6b2c66ceb6ea7", 3593750 * COIN),
std::make_pair("ae56a06345d6fd1b99360f5fc550e56390d11a5e", 3593750 * COIN),
std::make_pair("0f0cadd8c52961f5174185f28c82284280ccf82a", 3593750 * COIN),
std::make_pair("67df6fc4e2d47199d6026cdf1147ef1dbd620d92", 3593750 * COIN),
std::make_pair("7e2deee0940634e640b5dc10ae404aa0a1360e4f", 3593750 * COIN),
std::make_pair("b08c22942bafba6fc0db3a3ce3f2b9583609fed9", 3593750 * COIN),
std::make_pair("bd98440a3e6ab038c640561eea6405ae5371a387", 3593750 * COIN),
std::make_pair("b82fddcd3cbc38a271505a492d7c0f64db0929a4", 3593750 * COIN),
std::make_pair("442898f9dc13f5a1c9030a92b0e5eb91e4358eac", 3593750 * COIN),
std::make_pair("8b65be53c25194f76d927bc7243da5ad913817b0", 3593750 * COIN),
std::make_pair("33d3667bed812e4e478396ef76781addddfc5ffc", 3593750 * COIN),
std::make_pair("3f14c341372d80df8cba97da3d26a4adb90fac0c", 3593750 * COIN),
std::make_pair("b40d5aa2e350cb93363b0877305276bc589344f9", 3593750 * COIN),
std::make_pair("629d3576badeab0b065fe6e8303b60e1aa8a985b", 3593750 * COIN),
std::make_pair("da3bf0d1f548f58561204877f182af7967eda702", 3593750 * COIN),

// weather thank trophy perfect flip velvet object donkey light shuffle sure hole vivid ramp copy genius wagon vicious trust grant voice firm team submit
std::make_pair("b96ac9e78b278397496905991d6e1b58a109ccf0", 3593750 * COIN),
std::make_pair("9309c7ced2071208a9736256276f9212f16da005", 3593750 * COIN),
std::make_pair("7ac3dc450a509adf1d8fdd7b42f8921c05fc49b2", 3593750 * COIN),
std::make_pair("9a1c1eabe60f43d68d99553c46cc34bdbe01dab0", 3593750 * COIN),
std::make_pair("f8f0bc491ac5c7304cbb9f651f1314307a3eb1f8", 3593750 * COIN),
std::make_pair("a9258511f1e190d08173f12b094c9dea717e578a", 3593750 * COIN),
std::make_pair("2b80e3761ce79d20448603ccfae9f6b65bb56487", 3593750 * COIN),
std::make_pair("41df1852119373fe5346c39ea99ec3f76a083706", 3593750 * COIN),
std::make_pair("4dd48bcc5ab9354bc63db432df24e47ecac32f00", 3593750 * COIN),
std::make_pair("f559ab1765fe0ec3773975c8dc19d6667a426886", 3593750 * COIN),
std::make_pair("2b7e14646e027e15c37f3eec679f9b0fd9043382", 3593750 * COIN),
std::make_pair("805751e95ab28adc70611345b539e2a8c6c1c85f", 3593750 * COIN),
std::make_pair("886d82a71d6e1f63e669fae2d2af6166c24f1cc7", 3593750 * COIN),
std::make_pair("2723a0b297d88e068d2fd62b0f9de7103e26aafe", 3593750 * COIN),
std::make_pair("d6395d3772b448904e751d1dca6055c644e9819d", 3593750 * COIN),
std::make_pair("62730d00cb7fbbf89c2d4b3cc4f25cfeb17dc567", 3593750 * COIN),

// taxi denial bread sock chapter soap polar giraffe shoot unknown gown give exhaust curious stand party genuine crop chuckle battle off enjoy tornado suffer
std::make_pair("b7aafc8196598a89c580daf9566a66f833929cbe", 3593750 * COIN),
std::make_pair("598a8c8591cb20fd2b5b22faad7715dff0f13690", 3593750 * COIN),
std::make_pair("19ddbdf40533a95720187d83d825fa8bb69b8239", 3593750 * COIN),
std::make_pair("5d6d6a2ba081103fd66d1186e35f493d02850e55", 3593750 * COIN),
std::make_pair("9ac402d7c5f3a8d1934672d8f16a4f259ff48b98", 3593750 * COIN),
std::make_pair("09d0d846c5c21e331547c75c7dab3bd0051b15c3", 3593750 * COIN),
std::make_pair("6b677e70bb4aa3f0527cfd8384c24ada1c7dacf0", 3593750 * COIN),
std::make_pair("fd481042ea13e8c2ca53f66715ce30cca7fa1be8", 3593750 * COIN),
std::make_pair("4cc79733cffea438b9e45322ca9041aacd8c2890", 3593750 * COIN),
std::make_pair("73f76b740bc1e408f96508e2bdd27c02209c4c0a", 3593750 * COIN),
std::make_pair("0290e8a3c0b12a5dc4074a118d374ce653abc674", 3593750 * COIN),
std::make_pair("f546217531a2d92a1951dc9908b02cc5ebf594b6", 3593750 * COIN),
std::make_pair("01283b6db9a59a50eba6e5f31f4bf6d182aaeca7", 3593750 * COIN),
std::make_pair("3192a167ae7c8327209fadf488c45f21480beb9f", 3593750 * COIN),
std::make_pair("fb3dd8a065958318979d783bb16e20e6b3c7b15c", 3593750 * COIN),
std::make_pair("02e372e5b3fac62f535ce79952c65f666aef605a", 3593750 * COIN),

// say vapor tortoise glimpse sort pupil alter hat more spatial egg glide cost museum own limit remind glimpse accuse hope cabin clerk pull mammal
std::make_pair("c88acb22cc06a26c2bcd40ee93195dccf49b357b", 3593750 * COIN),
std::make_pair("5490d25f538880b24de931ef362bd9035cfc94f0", 3593750 * COIN),
std::make_pair("483eaf3d5faee47dfd55bd5edf36a5a81d5df0b9", 3593750 * COIN),
std::make_pair("3b64fc47ff824fa96c68b7879286f0d43af86e78", 3593750 * COIN),
std::make_pair("4c18b920fef85a1099725fe9fd05ad3520d7ce81", 3593750 * COIN),
std::make_pair("f5f024ef294baf167f96586f7e2a0cbf61c43527", 3593750 * COIN),
std::make_pair("d1bb4dff5b0ecb23456182f7f78536fb28d89404", 3593750 * COIN),
std::make_pair("09ad25f55a3f3d880c2fe382fa408c547e576917", 3593750 * COIN),
std::make_pair("dcdef85e3e2dc6d65c16953e8dbc80e73745e92b", 3593750 * COIN),
std::make_pair("e35a0e8685e248d7624facc70b4ab402cb1dd82d", 3593750 * COIN),
std::make_pair("3fa066566d792d30cc1c3b80145e311bc1ed2b59", 3593750 * COIN),
std::make_pair("d68d346eeffd96ece5ffeb249b1494462a263d5e", 3593750 * COIN),
std::make_pair("10297f75aa50affc42ed95d6dc32f819d380b668", 3593750 * COIN),
std::make_pair("c2d19b307d5b4e4a3eb8ebfdebdd6d5802adb41f", 3593750 * COIN),
std::make_pair("be8cc8a469e742a8faae1e1cfcce6fdeef5f5732", 3593750 * COIN),
std::make_pair("3656617b9b63fbe6c3910d21a745e6f4105bcce7", 3593750 * COIN),

// gauge future creek ritual hub polar stairs dumb welcome monitor domain outer surround subway novel blind person host wall pencil issue glory human sword
std::make_pair("91ae4104308e3db9753aac02e2474f142b67a655", 3593750 * COIN),
std::make_pair("fef3d464301b67a7560bf4176684d553c6b59af8", 3593750 * COIN),
std::make_pair("4602b9ae58d8b615d47b0255e9e422f8e324c691", 3593750 * COIN),
std::make_pair("8c42834caf04b562f9db77727b3195af0dab3147", 3593750 * COIN),
std::make_pair("2f4ccd96dd4b25b8fa1b1189ff1b8325fec0965a", 3593750 * COIN),
std::make_pair("654d1fca3ec5d8117b22e2ca93d72cdabd5bce2a", 3593750 * COIN),
std::make_pair("445ba8e7af98ce1c457ca852605cb6347a931818", 3593750 * COIN),
std::make_pair("5df64622c8cde3e02d413cb45f9ac7b4d7b3007b", 3593750 * COIN),
std::make_pair("160c640e0219c132d34c1993caccbbf04de48356", 3593750 * COIN),
std::make_pair("9e0ec817d2f619c43c8cc37bffe2df662f098f5c", 3593750 * COIN),
std::make_pair("72d655db6a3611fade9add2cf0c54e0d5c00e50a", 3593750 * COIN),
std::make_pair("2bdde69b7deca430181117f6053f68ece3d7e610", 3593750 * COIN),
std::make_pair("1fede9812746c9efef5a14f028ec64abc187cd62", 3593750 * COIN),
std::make_pair("1d3126946db712ae3d5c2caef3006e9919f15dfa", 3593750 * COIN),
std::make_pair("ceaa9ebdc7c1d4f8ab913562c888e9c560b41fd8", 3593750 * COIN),
std::make_pair("8e8818d48fb8eaf486810406a85de6bc924eef07", 3593750 * COIN),

// zebra quantum buffalo define fold judge fiction stamp ozone canvas state napkin fringe surface black snack team huge voyage announce pelican cigar castle sentence
std::make_pair("6e8f8e2fdf33f8e0b3cc8ad228d951146175bb45", 3593750 * COIN),
std::make_pair("52b50c00925f0b821f56988a6b35c9b59a6e3ffd", 3593750 * COIN),
std::make_pair("ee6339f7249d3352add32500077cee3469483588", 3593750 * COIN),
std::make_pair("6bacfd3646c41f2ea078703b57a80cd1307eb698", 3593750 * COIN),
std::make_pair("2f3f73c77095a9fe7c93f02bc195ece6eaa6b098", 3593750 * COIN),
std::make_pair("6258907733f6084db289ca223566c6fd1b584504", 3593750 * COIN),
std::make_pair("5ae78094c8ac01b9c752fd6882ad3021b045bc1a", 3593750 * COIN),
std::make_pair("87bd3b50e85c1cecb6a94341932a194acfd990b6", 3593750 * COIN),
std::make_pair("4955f0f6af183873859563511680a96f744c56ad", 3593750 * COIN),
std::make_pair("90e6b1d623573b171bd3bdca53427c77c3c239d9", 3593750 * COIN),
std::make_pair("14b53b76ccd42c495fdc6f8773b7b2587b30b48c", 3593750 * COIN),
std::make_pair("676b92863f0d7471a2c41d8393b3f71b8cdb8c94", 3593750 * COIN),
std::make_pair("6a2e6c5212804d57cfe342645f25013ad2f4848c", 3593750 * COIN),
std::make_pair("c0a613da2eb302f87ba2dbeafb2a26638c61789f", 3593750 * COIN),
std::make_pair("345d5fc333e065292bc2a80a5c6e1a0fbfb4f573", 3593750 * COIN),
std::make_pair("c2895fdb0e1e765d86847647c2de4e5af039f154", 3593750 * COIN),

// impact trust six oblige winter clap priority dial laundry royal symbol awake delay urge force sock course genuine theory blur nest cactus ripple earn
std::make_pair("50f83af10738c1c6626bf45cc651445a31d1c32f", 3593750 * COIN),
std::make_pair("7e3495050c8104a9348e730ce62e9d709960a634", 3593750 * COIN),
std::make_pair("2205d660d904ed52067d790d91d06d87ab33e293", 3593750 * COIN),
std::make_pair("d1c4a6433a57da1121003bfac25692619545fd89", 3593750 * COIN),
std::make_pair("a5c5a0fccff150e56456ca23a7ea3e1888aa423d", 3593750 * COIN),
std::make_pair("83e6223e82060cf9eb62ce2504f4b72a2eed1396", 3593750 * COIN),
std::make_pair("dba065217f11e8b9c6716160eefed649c8f9d032", 3593750 * COIN),
std::make_pair("0d857450942e67ac6811740168902ba231928cee", 3593750 * COIN),
std::make_pair("630e37c5527905d8d102be21664ca1d487bb0ef4", 3593750 * COIN),
std::make_pair("d6eeca9bf7ec59635ce5ec948f101d049a1c130f", 3593750 * COIN),
std::make_pair("6b3e0af06fd3017260689bcca4c5df63caee0029", 3593750 * COIN),
std::make_pair("27100a546df825e78e099e166bd5c32c8586e8d6", 3593750 * COIN),
std::make_pair("be04a981a90c5b1161a99498801db5e84731ef70", 3593750 * COIN),
std::make_pair("66947c58cad0ea423dd78a85468d8f5e505c779b", 3593750 * COIN),
std::make_pair("372bdfdd8ab25cffef4bd37067ec5a6701b3191f", 3593750 * COIN),
std::make_pair("f517baafeafbff74a135cebf10574790e2e64c97", 3593750 * COIN),

// erase concert over settle strike ten envelope half grocery liberty fatal traffic trade course latin lake faint awful deputy brand cake gas couch kid
std::make_pair("226e2ceee9cd857a0717df900e6002b362b5c13a", 3593750 * COIN),
std::make_pair("5118acbfbbf31e22a659f4bb19ab7d867fc598b1", 3593750 * COIN),
std::make_pair("8d2d51e8a53da7c9e44d9804a6a71450e819c876", 3593750 * COIN),
std::make_pair("6f91c1d80c01dc9f7c2376f5b6f3c41f9d758a00", 3593750 * COIN),
std::make_pair("643805e09159ef94a7f5e2d3117c54e365ccd862", 3593750 * COIN),
std::make_pair("5d48f14f186971d0f71896e9f1510a2bcca86b8b", 3593750 * COIN),
std::make_pair("f7ecb8da45a134ba6befd2ecd35b8790ad0d1a6a", 3593750 * COIN),
std::make_pair("5a60c77cf6d7f0ec04698c148c2bb5aabe8f3641", 3593750 * COIN),
std::make_pair("2b03a782238a5a14e0449c12e6c3e266e560aa63", 3593750 * COIN),
std::make_pair("54a638f2e4e8f1e7d4ee16e44fa7e2d93bdbbca4", 3593750 * COIN),
std::make_pair("bd85750a60e4d96c60867a4e18d5d503d8989bfe", 3593750 * COIN),
std::make_pair("eb4d0d675a851b636a9fe498bca8ed3b9f21f52e", 3593750 * COIN),
std::make_pair("bb3ca0ea324f4984a3a7b022bd76a7211d3b5281", 3593750 * COIN),
std::make_pair("3a45c0e7d896208043584d365b66202a8dbde224", 3593750 * COIN),
std::make_pair("d3e530f6fd5fc4ba95b5cf5ca443a91e7d9e84f2", 3593750 * COIN),
std::make_pair("6e346f4505a8993658c7535decdf5d39d05577ff", 3593750 * COIN),

// hurdle multiply pony there various stadium novel shop item basket bird candy misery alert exotic dog tail wood tumble movie merit egg tomorrow desk
std::make_pair("160d2b09989d8611539b442972a1872d84af5025", 3593750 * COIN),
std::make_pair("1600a6075a4d363d01ee6dea25da023c7b6129e3", 3593750 * COIN),
std::make_pair("7f26af76f9e90b9ceba60de4d09844dc0a7282f1", 3593750 * COIN),
std::make_pair("6d6a78ce1abccfa1ba41d967889fbe7ed85084f1", 3593750 * COIN),
std::make_pair("b38f24f66a693fd2c59ac7db0336184bc77394cc", 3593750 * COIN),
std::make_pair("22a8e38f04d6bdf02e1b2ea53b03cc0720fff397", 3593750 * COIN),
std::make_pair("72860abe3fbe99ce1e577e281c3360fe839e66c3", 3593750 * COIN),
std::make_pair("4326c0b15704b3c602f7b5471157177256c4a1df", 3593750 * COIN),
std::make_pair("5965d0882ec6cccb166614839961e59734dacdb9", 3593750 * COIN),
std::make_pair("24cce002be7a6ba7ea6a51303822a7b739106b00", 3593750 * COIN),
std::make_pair("b18b02ee5fa2bd4428944d7dbe1f0a5ad8ed1057", 3593750 * COIN),
std::make_pair("6a7fb4d71fff66075d08b15f4a4dfbc9001dc788", 3593750 * COIN),
std::make_pair("ae2f9e136771483bd7a56507e20a5c0fbbef836f", 3593750 * COIN),
std::make_pair("a48e748a31b8c073f6b5ea806c171b2109d63734", 3593750 * COIN),
std::make_pair("812b2b0f795d78f842aeda99a272da3bcbccd1e9", 3593750 * COIN),
std::make_pair("470d4924986216554cd198deffa479b506cff2ed", 3593750 * COIN),

// panel prosper silk post easily fashion acid escape flock senior style inject unveil excite dry drum beef oven advance pear loop rain brisk mountain
std::make_pair("5e245b3c90626afa60d44c18471c5bcc3cf1b672", 3593750 * COIN),
std::make_pair("d3812ab1b7e98124655d718ca012e0e3e467a3df", 3593750 * COIN),
std::make_pair("e5a12543ded8ce659378e7c7d1c59fb4c32346a2", 3593750 * COIN),
std::make_pair("634c3b055e28d5b8cd874d5d1ccb90d601776cd1", 3593750 * COIN),
std::make_pair("a8c0599ba82910eaad71e2d05989aebc8ba13a12", 3593750 * COIN),
std::make_pair("d5a42374403a77edc142c9bdfebdbd69cf86cecb", 3593750 * COIN),
std::make_pair("54828ba836ee6cc455e24b9757a5f2e1cd66e567", 3593750 * COIN),
std::make_pair("511b32229815a5d14e549299f6c1c37750cf28d0", 3593750 * COIN),
std::make_pair("c5ed0ef8833f8d2d814e572bbd40d6ee0e5fa341", 3593750 * COIN),
std::make_pair("b44a1e8540de1402077848f950b467f7cc3a361f", 3593750 * COIN),
std::make_pair("da7f947ce18f9ca0d77b824717c7ff7897244b45", 3593750 * COIN),
std::make_pair("5fbc5ae4e6d0dbf924852ab4e7961e7ec2075c24", 3593750 * COIN),
std::make_pair("b613fc259b6b51593956d23ccee6d345a6db3720", 3593750 * COIN),
std::make_pair("eec43c3d4ec6413a8bac081739280935fee03b53", 3593750 * COIN),
std::make_pair("c5f291edcaf6af0cbd3211ed93220b1ac90a5429", 3593750 * COIN),
std::make_pair("118f572f11c9b341b8b9ff2b780557c1a391542a", 3593750 * COIN),

// east episode surge demise pepper vast bind fantasy cancel puppy foot breeze bean hunt couple alarm where idle tag umbrella input you engage day
std::make_pair("b7fab5c01a1b3559f6afc27a5bb738053e012b39", 3593750 * COIN),
std::make_pair("686236e754b677651f1762a9685043ad957b6c86", 3593750 * COIN),
std::make_pair("7a2f972eedc4ef61fdb75527a70fe3a89a6ed772", 3593750 * COIN),
std::make_pair("4b0cc822da9fb3c0d74afb6dd1bcac78b2164a97", 3593750 * COIN),
std::make_pair("967f3256d7df3cb8255b9daa897544717ab0376c", 3593750 * COIN),
std::make_pair("58a49494541a2eed4529abd8b26cb43930cbc0ff", 3593750 * COIN),
std::make_pair("eba267a9b000b0961f7855c6a8518d0249479eb2", 3593750 * COIN),
std::make_pair("83538092564c13e6d89753a0bba8fe1e0cc02333", 3593750 * COIN),
std::make_pair("f8dd404b294990501b17606da12114c3a9685a42", 3593750 * COIN),
std::make_pair("cb016a200ab264363ffb1fa95c1a2b0e60023016", 3593750 * COIN),
std::make_pair("6fd942b4e23a5a8793fb96d7644f2134ee1c88b5", 3593750 * COIN),
std::make_pair("36afa44aab9deb084b037e9be763a8fb87cef6ed", 3593750 * COIN),
std::make_pair("75a420cefe21a1d1d16cbb1fddf254d8651adc99", 3593750 * COIN),
std::make_pair("a2a2609add4beebac98d631ec8162b728dd926d4", 3593750 * COIN),
std::make_pair("062e38896e67610c907096b59ee42adb75bae1ca", 3593750 * COIN),
std::make_pair("c54c8bc298096adc279e3f779409fae7f8246853", 3593750 * COIN),
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
        genesis = CreateGenesisBlockMainNet(1523355070, 113291, 0x1f00ffff); // 2017-07-17 13:00:00
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0000518ad03c59a86c3065d90d4cc199b37704c0a81ec4dda29c69419fea657c"));
        assert(genesis.hashMerkleRoot == uint256S("0x00b78d44a74d87eacfa01992d6c885ab91b11d78c1332b4766af82182eb0478b"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x191a3e13fd14e12a0b6cd92f7423bd745df960f1eb0ed57124f23ec37f967962"));

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

