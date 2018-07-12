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
    // film exile belt monster manual scheme cigar move hope idea fade similar title segment custom venue open earn bubble deposit drift rib ribbon document
    std::make_pair("8a3a53ae34b822639a054041742c2d564a7cc617", 10000 * COIN),
    std::make_pair("109d97bb0b5edbdebb68bc7781c333e783e8518a", 10000 * COIN),
    std::make_pair("3ce5bc269c7023d98747833d744f0b3c71ecd38e", 10000 * COIN),
    std::make_pair("5c0e641234606f7d9026e0cc1517c8f430678b28", 10000 * COIN),
    std::make_pair("097e284e46e13bd4cbc9d7a54e4ea56b4ca1c6de", 10000 * COIN),
    std::make_pair("0bfdd975f86074052bfcd23e6d119420e0b0b3eb", 10000 * COIN),
    std::make_pair("1069c8d1e2a8aebf92c60ae648c0ef943f7b782d", 10000 * COIN),
    std::make_pair("f88195ecc73190f4d8d500ec4e192093718cac60", 10000 * COIN),
    std::make_pair("6b645b023c9f51643d1ee3192a272c2ff255c4b4", 10000 * COIN),
    std::make_pair("37766b937459fae0444d222d7f914d4f4719160b", 10000 * COIN),
    std::make_pair("9e56ac963a960b0a291f483f58e7e80ff33e4253", 10000 * COIN),
    std::make_pair("2d67bdd5713d08f34f465cb7439941efc6daac50", 10000 * COIN),
    std::make_pair("6a96a97b7c21e8c371f0b09326ba5f70084d2b54", 10000 * COIN),
    std::make_pair("f9f9b7e777be2546b0ec660f83d7d67aa195d17b", 10000 * COIN),
    std::make_pair("011557a0b78bf186f14924ac76a5c71d6dc3d5d0", 10000 * COIN),
    std::make_pair("030d42fcd5265219ff150378e61ad4d7476017ce", 10000 * COIN),
    std::make_pair("1ab8f86fd3d97b07a4e06b91c07f891fadc8463a", 10000 * COIN),
    std::make_pair("d55588353d09c1a892021a21171f0c3aa13d38f8", 10000 * COIN),
    std::make_pair("fff9f860e651cc67d88a24673f3409280e7cce5d", 10000 * COIN),
    std::make_pair("f5ef6e0bb475c27a09de3221ac88d5182aba2b45", 10000 * COIN),

    // theory talk empower critic lobster dinner zoo dumb trial repair fantasy orchard this write master wave hurt basic bonus just power pioneer primary work
    std::make_pair("560f13232449d34a6068931fe4d1e29f73cd16d6", 10000 * COIN),
    std::make_pair("71facb4f3baecc8ef591ebfe7213020dacccd09f", 10000 * COIN),
    std::make_pair("fdf5174fd16fe0239543771a7bfbc13652bdf2d9", 10000 * COIN),
    std::make_pair("5feb58f05ef3ffc065eccf626d9687f79104d085", 10000 * COIN),
    std::make_pair("b77965caf3555f54d99e74a3e72817554958a2fd", 10000 * COIN),
    std::make_pair("d893ecd6be6c727e24395a1f900050278e6f72af", 10000 * COIN),
    std::make_pair("2bbe82e85d0d66cd3e4b00d8e002c7dcb0acf8a1", 10000 * COIN),
    std::make_pair("205a51e68838eb6e0c656c600d768431443ffb25", 10000 * COIN),
    std::make_pair("36462512c82a8b89309f8ec1f61d338ae56969e5", 10000 * COIN),
    std::make_pair("005ae75dd48b063443774cf9fab7c133701a7d47", 10000 * COIN),
    std::make_pair("568544ef9a751ea9ad2a12c9630080db07af46bb", 10000 * COIN),
    std::make_pair("64a0966a29483c1a2ab39e33c3fa2395344ee928", 10000 * COIN),
    std::make_pair("370818d471bf78e13d10e3d28fa0f8120502b8cc", 10000 * COIN),
    std::make_pair("f249eeb61c14a65f1810c925d73f1a713a9ccf53", 10000 * COIN),
    std::make_pair("0a9ce077c7aa461f539a30f8c3b855e60aa94ae2", 10000 * COIN),
    std::make_pair("347f0d1a1ea49c27b6891bc6970fda6f5abcf7c1", 10000 * COIN),
    std::make_pair("b5b560f0ecae00ffa039cd1cf0734e83e1a26a70", 10000 * COIN),
    std::make_pair("44d59c8813066afda62d96907a60c26edc0aac00", 10000 * COIN),
    std::make_pair("cbd69ce1649de9065483fb06cfd1138bfc0a40ad", 10000 * COIN),
    std::make_pair("80f0836166dce941d681555b9c9cf9d4eed61cdd", 10000 * COIN),

    // boat speak clown frequent ill rude little twenty lizard spread charge scrap limb sentence broccoli where rhythm guard idea clay slam limb heavy call
    std::make_pair("9d49cd525908e1ac28cb74b079e9cda3183902e4", 10000 * COIN),
    std::make_pair("70513aab0ca4e02ab6b3289ed75acde59451fae7", 10000 * COIN),
    std::make_pair("02c8868e65450a8904932fbac93408e947a4ad25", 10000 * COIN),
    std::make_pair("ed406a644fcdbfa89d816058d03f2b97b103dd71", 10000 * COIN),
    std::make_pair("e26c8ef924602a039142be49f98911698739de1e", 10000 * COIN),
    std::make_pair("537f0ef7d12d1d4c53d0859cff3d78a93d1035d7", 10000 * COIN),
    std::make_pair("e42bee700fd2f89cad2c33c4dbeaca461303276b", 10000 * COIN),
    std::make_pair("63cc0721b5c61171a767f37bb9a24689590baba3", 10000 * COIN),
    std::make_pair("609438f1e49380ff997b222493727b3a6212a16f", 10000 * COIN),
    std::make_pair("0e6143e6674f9161e490149f9bfcaa487f14273d", 10000 * COIN),
    std::make_pair("c3bafd1a0eab2ccc7fc7ddbfaefb546911e09cfd", 10000 * COIN),
    std::make_pair("cda7a42c87c6206b7734a2fad1d001d8c385274e", 10000 * COIN),
    std::make_pair("4486bf2f5ec5c7b117a91001a069cd99253bdbf0", 10000 * COIN),
    std::make_pair("7d7ee79038bf29811a05ed7d7516d21e927042ca", 10000 * COIN),
    std::make_pair("252f7d76b150040cefab4913920db8cae320cbc8", 10000 * COIN),
    std::make_pair("441b9b0d6bcc00f1fb24b650cd755694df41f409", 10000 * COIN),
    std::make_pair("a99291756da4b2f629e4f3fa5441265fb3d989c2", 10000 * COIN),
    std::make_pair("7dfd11b2d2939e7e3825d824db8cdc41f52e0cc3", 10000 * COIN),
    std::make_pair("34577b2942973e77e6412fde623d09855c46b4e5", 10000 * COIN),
    std::make_pair("f819bdf36c71a604884500dea28994117ecde3b0", 10000 * COIN),

    // mirror time worth wine length hospital coral service buyer evolve imitate ginger rail build glare cup human quit write road climb toddler space fee
    std::make_pair("d02fb3515a75c1501cec14f01e29a3617c26a58b", 10000 * COIN),
    std::make_pair("246b95937dc18f276253701f2bdbb7852bd1f55f", 10000 * COIN),
    std::make_pair("7818ec748abcb6bd3b20df89c5ecaf8cd10d7da9", 10000 * COIN),
    std::make_pair("35ed8b4755be02927e2d1af89d9e3d3bc552cb61", 10000 * COIN),
    std::make_pair("d57925aa5e48cc79bbd2b9be13e95a6bd99f836c", 10000 * COIN),
    std::make_pair("388cb3f98ef0987ba5c9eee1518a2fc81fcc143d", 10000 * COIN),
    std::make_pair("342eb5d92a142fb93f62ebc3066ea3a3c38bc5d7", 10000 * COIN),
    std::make_pair("2aa5d23c782f4b2c8d22baed9ec996a4b7889c96", 10000 * COIN),
    std::make_pair("36fd13c370fd0d6b5bb9d5e0f766069dba8c93f8", 10000 * COIN),
    std::make_pair("84dbd920e179a11093f000bd6e768757ed457313", 10000 * COIN),
    std::make_pair("2ac7fbf99b9971d4e8cda50abb4499a0d7b599c2", 10000 * COIN),
    std::make_pair("73eb6d851d3efcacadf964e6b1bb4a58b8e599fe", 10000 * COIN),
    std::make_pair("ebd5494fdcdc883ebc961a37eb1dd3ff1bc50ee2", 10000 * COIN),
    std::make_pair("69a9fef0446d34ad722451d3379310a7e472228a", 10000 * COIN),
    std::make_pair("c27c173f36257575f6da90f19e275b058c168a2a", 10000 * COIN),
    std::make_pair("6a07c8b9065df791abf8f61950abea255287a5af", 10000 * COIN),
    std::make_pair("dd48b0846109bfc1d70f22fc9b557ec71f78c566", 10000 * COIN),
    std::make_pair("6f67673c98a145aea3c30a2b8a77cc022ef9468b", 10000 * COIN),
    std::make_pair("484d22391024718d75fd29966d99bf75fa78f411", 10000 * COIN),
    std::make_pair("e0105bcf4ae4a3736103da9ba405fb3bad9cdf3a", 10000 * COIN),

    // child lyrics unusual gap wonder cereal attack social wreck canyon armed cheap call shift team lake supply payment subway alpha outdoor jealous manual stay
    std::make_pair("f40950789507ef3c04df7dc3d194aa98b4b5fdc8", 10000 * COIN),
    std::make_pair("0025f9eae90a0dc92f0d026d914df0bb2cb57bc0", 10000 * COIN),
    std::make_pair("e00593378e3ebb189fab94750dff75b316b046d6", 10000 * COIN),
    std::make_pair("d5fa7731ee044d776633916df96cd8a8e479f7b5", 10000 * COIN),
    std::make_pair("1d121c99896fd5b91a711d2dd6a2c385b3b30715", 10000 * COIN),
    std::make_pair("f2112cdb24cd75ed3dfa5d1a868f26b430fcae57", 10000 * COIN),
    std::make_pair("ade5b94fe00f4b944a9b8a90962b3470d776b457", 10000 * COIN),
    std::make_pair("2254636c8dd5f6ce110babc81a35ea3f67d664d6", 10000 * COIN),
    std::make_pair("75bb4a647a32cf164c6aaefcc23ec238d667693b", 10000 * COIN),
    std::make_pair("7cc589df683fdc097ca2d532d0e39a048f862b09", 10000 * COIN),
    std::make_pair("d88677e5f0fbd17b10d35ce3b3adff933132d242", 10000 * COIN),
    std::make_pair("7b66027fab10bf12c1c3ebe272e49c6f3a692217", 10000 * COIN),
    std::make_pair("0590e0a1ac5ff93a95bc69aac1c49a2b367d8d43", 10000 * COIN),
    std::make_pair("c85abb76f9a6ca3e717b61244757cdc98ab53e7c", 10000 * COIN),
    std::make_pair("4e446cc08cbeb018188a064378e49fe7f9282789", 10000 * COIN),
    std::make_pair("c3a70cb8efa07fefba4cf55cbb691e42d422fffa", 10000 * COIN),
    std::make_pair("e351d47340b8c867dffa0d9c2fed2739da2c8f79", 10000 * COIN),
    std::make_pair("9c63c32c8746cebbcd134b69425679ab6cdf9e59", 10000 * COIN),
    std::make_pair("61e0ce67f843661962ae06f10775dcb70b84f48b", 10000 * COIN),
    std::make_pair("4bf4cf7eee226c5273d6c531a49609a4a6995acf", 10000 * COIN),

    // word crystal exact execute kid cross various scorpion height axis cigar push pride ramp canvas hope twenty six tower horn slim sunset broom unique
    std::make_pair("1e295358b96ad99e94e8e6ecf53d0fa91427603c", 10000 * COIN),
    std::make_pair("a84ca0c7b58a1046c4480942e1b4ec39da0a4ab1", 10000 * COIN),
    std::make_pair("61fdf8b3c7a85a6914c87e01bb05938911d4e2b2", 10000 * COIN),
    std::make_pair("cbc212264e27f550fd91498cff49d5babe8240b4", 10000 * COIN),
    std::make_pair("1ac0db89aa5afc0af9db712aac5c6106d7275070", 10000 * COIN),
    std::make_pair("b018f50f1867db326e7a8220b4c9c07768adc8d4", 10000 * COIN),
    std::make_pair("eeb71024333d0c310de7d77c94504babecf782ef", 10000 * COIN),
    std::make_pair("cb47dcd951d69c2c420ee06dfa1d8b8df2a2ccba", 10000 * COIN),
    std::make_pair("58e04a08fe2bbd83058aff276b788de404d23ea6", 10000 * COIN),
    std::make_pair("6d245740da011b69a16cc1b5544e560000d66bbb", 10000 * COIN),
    std::make_pair("1f00836d06344445084cd95a01e9d98d82107c98", 10000 * COIN),
    std::make_pair("30086002244ed713c39098b80aea3041acfd86e9", 10000 * COIN),
    std::make_pair("37fc59d370722a6dd5cf941df5ded2452402ee61", 10000 * COIN),
    std::make_pair("d9afe2c30d5a991ea4ebc22405401af4bdd25700", 10000 * COIN),
    std::make_pair("2e193ded8160989bc2da4339cdce3ec6c6fb9f3c", 10000 * COIN),
    std::make_pair("cfb789e8968356a5657953e93205cbea5f4952d7", 10000 * COIN),
    std::make_pair("9e46b18122ba7996aae6643bcd54c38bb3dda990", 10000 * COIN),
    std::make_pair("7fe9aab42f828f231c0a4581cbaa619b0e718b79", 10000 * COIN),
    std::make_pair("d5ce2b252720b6933d3a2f20527827d08c22256b", 10000 * COIN),
    std::make_pair("3f442437b35d8fa11bcfa2d12ee15f993e0be788", 10000 * COIN),

    // assume grid steel erupt amateur hunt various dream cake hungry work tongue soon hurry old pyramid neutral shock among nothing like emotion into include
    std::make_pair("4cef4306fe0e3b7097a43bec4198c14f30710cce", 10000 * COIN),
    std::make_pair("37fe80bc4540d56c34da420d8f41170cbded44b6", 10000 * COIN),
    std::make_pair("ce714ece32df80de73e971193581bd42d122f820", 10000 * COIN),
    std::make_pair("3492ed590735b4f877d350e3d493440c959b3c0a", 10000 * COIN),
    std::make_pair("4d0bc42ec8231526f33473e3c32d216432379680", 10000 * COIN),
    std::make_pair("8c29fec0da0f10d5331b0ddd616dcf77653b870e", 10000 * COIN),
    std::make_pair("11dd690e40e84f899f9494d82ba78aa9dea2554e", 10000 * COIN),
    std::make_pair("c596c76924dbbe12503b42c932a85a290b4bbe37", 10000 * COIN),
    std::make_pair("e186674b65125eab56438462bb304a14d6057a12", 10000 * COIN),
    std::make_pair("4f7cb9ee8c61ceb36513ded34ecd4586bcf6dec9", 10000 * COIN),
    std::make_pair("798eab27b1c8652e145bd89545ea2b850e5f2dae", 10000 * COIN),
    std::make_pair("47aa3f5a64530151e87afb8ba3568ab5473f7476", 10000 * COIN),
    std::make_pair("4a4d70d517393670471d9c96d39cc86587765fbf", 10000 * COIN),
    std::make_pair("aa296a6851f2ccaefd7524bad5383f264a78caf6", 10000 * COIN),
    std::make_pair("1b3d6b477d2dc2efb9896790cac33f1c16a5a14f", 10000 * COIN),
    std::make_pair("97877363f3ed211cbc9b14fd345707b3df2b2e60", 10000 * COIN),
    std::make_pair("96eecaa06652aa60aaeca32b8c8f91c45542895b", 10000 * COIN),
    std::make_pair("c9068d1b2979642b6bc4b0674216a9fbce839b6a", 10000 * COIN),
    std::make_pair("d54c5641f6866229ae7c426034ebe7eb7fcbc1dc", 10000 * COIN),
    std::make_pair("7229fbe12db5591ef6902fbe30b59d2c3a7e3ced", 10000 * COIN),

    // edge clock captain animal stone win expose choose home suggest traffic law dash hire toast humble north ocean virtual sand filter nothing vivid style
    std::make_pair("c20f083afa105837582afa0f6bd065bac2644b3a", 10000 * COIN),
    std::make_pair("d7ee76ee34384c9cb95ed5b1236ed066d6d3b8b3", 10000 * COIN),
    std::make_pair("17cf7e03ed1ebe709263cd270a10170533100d42", 10000 * COIN),
    std::make_pair("95452f439989be890806fa27232556102a6cba25", 10000 * COIN),
    std::make_pair("fdba6b0d165f42789d619ed46b3d51f7a17ee56e", 10000 * COIN),
    std::make_pair("5ae6a998199d0e680a11112e3cfb315580bd3935", 10000 * COIN),
    std::make_pair("dc1a238a2038e1e6a91b24676f5fa228f1a964d2", 10000 * COIN),
    std::make_pair("663092e1b0649e836b422812d4ecafc173feb6cf", 10000 * COIN),
    std::make_pair("bd7ffe474ac683a497358335a6540d5ce9187cc9", 10000 * COIN),
    std::make_pair("eac98986f35568dabad7e162a079406aa3c68c27", 10000 * COIN),
    std::make_pair("e382b451674f3f285884391f5c4c8785a9e46f3c", 10000 * COIN),
    std::make_pair("968415719ab58485c79c9e09d38d720a67c16926", 10000 * COIN),
    std::make_pair("c5903df5d0e89771318614e7cfda38edb7100b8a", 10000 * COIN),
    std::make_pair("3209d09aaee3b03f993df17c4d2e4fb220402887", 10000 * COIN),
    std::make_pair("98a98251d0358d9a0fd9d1bf27881aae2235b485", 10000 * COIN),
    std::make_pair("f72615720e2eb4e86619d35b121dd001a3750e27", 10000 * COIN),
    std::make_pair("8e35e8b283f80a45f747f44f7530908072a1afe8", 10000 * COIN),
    std::make_pair("96031fd6b69257213addfa81cd8213fe9654d358", 10000 * COIN),
    std::make_pair("9af294365f1edba8acfb39046dec8aa7cbd1c466", 10000 * COIN),
    std::make_pair("df8de74c2cbe6cc11a8d18d0a39350b94e3bc010", 10000 * COIN),

    // push interest poet oyster sister finish person upset relax desk tattoo blue spatial candy dish verb help cool buddy morning enough exclude only sugar
    std::make_pair("32fae39198271c943a17dce60735f984df04c0f6", 10000 * COIN),
    std::make_pair("369b4c0ca2d613039adeecf3c79f6fbd41df6239", 10000 * COIN),
    std::make_pair("1b2bf4a39c5ab513721bc8f50619ccf8ffd5de3f", 10000 * COIN),
    std::make_pair("ad5f9ac8e82c1dae774866b328d0f00a3a0f5959", 10000 * COIN),
    std::make_pair("0056a162d6713f510c6fadeb03b3681334b5792f", 10000 * COIN),
    std::make_pair("2f419c86503f5c053806f6f19d9433d30d9f9421", 10000 * COIN),
    std::make_pair("d513c48679e290deb7e65ab6379f769aadd8a4b7", 10000 * COIN),
    std::make_pair("170a2990f06b6f951a6c54769bd095a2f1a3fdd0", 10000 * COIN),
    std::make_pair("118245eb2bf6339c200d55f286baedff44566d9d", 10000 * COIN),
    std::make_pair("509d547902261d0d7fc3a0fab6cf02e2fe5e655f", 10000 * COIN),
    std::make_pair("34b58dbd375072701ddd832c92881f5850de2cb1", 10000 * COIN),
    std::make_pair("d2879c2c026f9502ef7f54df0224065bb22e7c5e", 10000 * COIN),
    std::make_pair("ff74b0532763603a78d3c74978abeaf48f5c03cf", 10000 * COIN),
    std::make_pair("e84ae01cce25923b3d59c5a4c0bd7e95828e1bd4", 10000 * COIN),
    std::make_pair("b6040e711b1a7c5308ae435a6a536033ed32dbdd", 10000 * COIN),
    std::make_pair("b95764d9f835a4da3505290a40075703693014ed", 10000 * COIN),
    std::make_pair("621320968e1fd2d75968a0f9e120569c63795871", 10000 * COIN),
    std::make_pair("1755ab45f86d5d8759739eb0c1de4590f0b13afc", 10000 * COIN),
    std::make_pair("f1c236a7c8fe6731589f03e9b1287a0d15a21d61", 10000 * COIN),
    std::make_pair("7a3f7e0c8c08195046ddd33c5eb52cd0511889b1", 10000 * COIN),

    // person apart fantasy tell category swap crop morning devote endorse spin utility upset ladder buzz make exhaust panic slow oxygen coin suffer chuckle bind
    std::make_pair("243280090ef958e9adfb4aeb3316c7dca5690943", 10000 * COIN),
    std::make_pair("646498d36075f22b70bc452c41261602260653f7", 10000 * COIN),
    std::make_pair("47b16f2185c1cca1994686d12656bf15f69c0ec7", 10000 * COIN),
    std::make_pair("008de01fb1ea8f62591b2c54cf85a29c544ab9c8", 10000 * COIN),
    std::make_pair("835f0f5515cbe9a1f626ce10c37fba85b59660a1", 10000 * COIN),
    std::make_pair("a01fb9d9dd069f88a4cccce5944e007132123c9c", 10000 * COIN),
    std::make_pair("8aa29e76baf76d1b111b211943b7245061139c2c", 10000 * COIN),
    std::make_pair("b6254de3820e90e794e056c8d548360874605083", 10000 * COIN),
    std::make_pair("32b8da05da1c37943f2ec25262e15ddf35b02247", 10000 * COIN),
    std::make_pair("3b11da06bd66e949c0cb02d9e432d899e178d3a8", 10000 * COIN),
    std::make_pair("98c36dab236903b9398508a2bcd0717475268b27", 10000 * COIN),
    std::make_pair("adf2e1f191a0ce043cfc45da9319f9cd3cdb3d4f", 10000 * COIN),
    std::make_pair("f2f147b71c2b4d9891fa4446bf4e1d7ffcbd0f13", 10000 * COIN),
    std::make_pair("b0d0aaf5564fe59f6d76915867af7cc8809e88ce", 10000 * COIN),
    std::make_pair("739537a7ec2b47f813a067a56731d7c2bb41c70f", 10000 * COIN),
    std::make_pair("0be405f41efddd31cd8f1734ebd973fafb267b99", 10000 * COIN),
    std::make_pair("f4315cf4338ac734dad84c1ff33b89439a686fb6", 10000 * COIN),
    std::make_pair("ed5b00b19c1dab4bb407d4834f5a57a8968b9faa", 10000 * COIN),
    std::make_pair("bd6a628ea8e5f5737d412647b126704af1d0b314", 10000 * COIN),
    std::make_pair("92083fc7dd93a4d82061605090bc0bbf9e2d3d2a", 10000 * COIN),
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
        nStakeMinConfirmations = 20;   // 225 * 2 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        // No need to import coinbase transactions.
        // AddImportHashesMain(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 100000;

        // Create MainNet genesis block
        genesis = CreateGenesisBlockMainNet(1523355070, 17923, 0x1f00ffff); // 2017-07-17 13:00:00
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x000070bd6cdb8422afdf9064e96c51ffbeb14fde42d3baaea01f71dada00959c"));
        assert(genesis.hashMerkleRoot == uint256S("0x5eea821b1137869ec115b8de60196262ef3d135f6f105a479dcdb4b323001571"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0xe66b6c36a5788957093eaaa8db7ba3f64aa79060a246a606b07525e63272ef6f"));

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

