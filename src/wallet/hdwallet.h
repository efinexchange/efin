// Copyright (c) 2017 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_WALLET_HDWALLET_H
#define PARTICL_WALLET_HDWALLET_H

#include "wallet/wallet.h"
#include "wallet/hdwalletdb.h"
#include "wallet/rpchdwallet.h"

#include "key/extkey.h"
#include "key/stealth.h"

#include "../miner.h"

typedef std::map<CKeyID, CStealthKeyMetadata> StealthKeyMetaMap;
typedef std::map<CKeyID, CExtKeyAccount*> ExtKeyAccountMap;
typedef std::map<CKeyID, CStoredExtKey*> ExtKeyMap;

typedef std::map<uint256, CWalletTx> WalletTxMap;


class CTempRecipient
{
public:
    CTempRecipient() : nType(0), nAmount(0), fSubtractFeeFromAmount(false) {};
    CTempRecipient(CAmount nAmount_, bool fSubtractFeeFromAmount_, CScript scriptPubKey_)
        : nAmount(nAmount_), fSubtractFeeFromAmount(fSubtractFeeFromAmount_), scriptPubKey(scriptPubKey_) {};
    
    uint8_t nType;
    CAmount nAmount;
    bool fSubtractFeeFromAmount;
    CTxDestination address;
    CScript scriptPubKey;
    std::vector<uint8_t> vData;
    std::vector<uint8_t> vBlind;
    CKey sEphem;
    CPubKey pkTo;
    int n;
    std::string sNarration;
};


class CHDWallet : public CWallet
{
public:
    CHDWallet(const std::string &strWalletFileIn)
    {
        strWalletFile = strWalletFileIn;
        SetNull();
        fFileBacked = true;
        nReserveBalance = 0;
        
        pEKMaster = NULL;
    };
    
    ~CHDWallet()
    {
        Finalise();
    };
    
    int Finalise();
    int FreeExtKeyMaps();
    
    static bool InitLoadWallet();
    
    bool LoadAddressBook(CHDWalletDB *pwdb);
    
    bool LoadVoteTokens(CHDWalletDB *pwdb);
    bool GetVote(int nHeight, uint32_t &token);
    
    bool EncryptWallet(const SecureString &strWalletPassphrase);
    bool Lock();
    bool Unlock(const SecureString &strWalletPassphrase);
    
    bool HaveKey(const CKeyID &address) const;
    
    bool HaveExtKey(const CKeyID &address) const;
    
    bool GetKey(const CKeyID &address, CKey &keyOut) const;
    
    bool GetPubKey(const CKeyID &address, CPubKey &pkOut) const;
    
    bool HaveStealthAddress(const CStealthAddress &sxAddr) const;
    
    bool ImportStealthAddress(const CStealthAddress &sxAddr, const CKey &skSpend);
    
    bool AddressBookChangedNotify(const CTxDestination &address, ChangeType nMode);
    bool SetAddressBook(CHDWalletDB *pwdb, const CTxDestination &address, const std::string &strName,
        const std::string &purpose, const std::vector<uint32_t> &vPath, bool fNotifyChanged=true);
    bool SetAddressBook(const CTxDestination &address, const std::string &strName, const std::string &purpose);
    bool DelAddressBook(const CTxDestination &address);
    
    isminetype IsMine(const CTxOutBase *txout) const;
    bool IsMine(const CTransaction& tx) const;
    bool IsFromMe(const CTransaction& tx) const;
    
    /**
     * Returns amount of debit if the input matches the
     * filter, otherwise returns 0
     */
    CAmount GetDebit(const CTxIn& txin, const isminefilter& filter) const;
    CAmount GetDebit(const CTransaction& tx, const isminefilter& filter) const;
    
    CAmount GetCredit(const CTxOutBase *txout, const isminefilter &filter) const;
    CAmount GetCredit(const CTransaction &tx, const isminefilter &filter) const;
    
    CAmount GetBlindBalance();
    CAmount GetAnonBalance();
    CAmount GetStaked();
    
    bool IsChange(const CTxOutBase *txout) const;
    
    int GetChangeAddress(CPubKey &pk);
    
    int AddStandardInputs(CWalletTx &wtx,
        std::vector<CTempRecipient> vecSend,
        CExtKeyAccount *sea, CStoredExtKey *pc,
        std::string &sError);
    int AddStandardInputs(CWalletTx &wtx, std::vector<CTempRecipient> vecSend, std::string &sError);
    
    
    bool LoadToWallet(const CWalletTx& wtxIn);
    
    /** Remove txn from mapwallet and TxSpends */
    int UnloadTransaction(uint256 &hash);
    
    int GetDefaultConfidentialChain(CHDWalletDB *pwdb, CExtKeyAccount *&sea, CStoredExtKey *&pc);
    
    int ExtKeyNew32(CExtKey &out);
    int ExtKeyNew32(CExtKey &out, const char *sPassPhrase, int32_t nHash, const char *sSeed);
    int ExtKeyNew32(CExtKey &out, uint8_t *data, uint32_t lenData);
    
    int ExtKeyImportLoose(CHDWalletDB *pwdb, CStoredExtKey &sekIn, CKeyID &idDerived, bool fBip44, bool fSaveBip44);
    int ExtKeyImportAccount(CHDWalletDB *pwdb, CStoredExtKey &sekIn, int64_t nTimeStartScan, const std::string &sLabel);
    
    int ExtKeySetMaster(CHDWalletDB *pwdb, CKeyID &idMaster); // set master to existing key, remove master key tag from old key if exists
    int ExtKeyNewMaster(CHDWalletDB *pwdb, CKeyID &idMaster, bool fAutoGenerated = false); // make and save new root key to wallet
    
    int ExtKeyCreateAccount(CStoredExtKey *ekAccount, CKeyID &idMaster, CExtKeyAccount &ekaOut, const std::string &sLabel);
    int ExtKeyDeriveNewAccount(CHDWalletDB *pwdb, CExtKeyAccount *sea, const std::string &sLabel, const std::string &sPath=""); // derive a new account from the master key and save to wallet
    int ExtKeySetDefaultAccount(CHDWalletDB *pwdb, CKeyID &idNewDefault);
    
    int ExtKeyEncrypt(CStoredExtKey *sek, const CKeyingMaterial &vMKey, bool fLockKey);
    int ExtKeyEncrypt(CExtKeyAccount *sea, const CKeyingMaterial &vMKey, bool fLockKey);
    int ExtKeyEncryptAll(CHDWalletDB *pwdb, const CKeyingMaterial &vMKey);
    int ExtKeyLock();
    
    int ExtKeyUnlock(CExtKeyAccount *sea);
    int ExtKeyUnlock(CExtKeyAccount *sea, const CKeyingMaterial &vMKey);
    int ExtKeyUnlock(CStoredExtKey *sek);
    int ExtKeyUnlock(CStoredExtKey *sek, const CKeyingMaterial &vMKey);
    int ExtKeyUnlock(const CKeyingMaterial &vMKey);
    
    int ExtKeyCreateInitial(CHDWalletDB *pwdb);
    int ExtKeyLoadMaster();
    int ExtKeyLoadAccounts();
    
    int ExtKeySaveAccountToDB(CHDWalletDB *pwdb, CKeyID &idAccount, CExtKeyAccount *sea);
    int ExtKeyAddAccountToMaps(CKeyID &idAccount, CExtKeyAccount *sea);
    int ExtKeyRemoveAccountFromMapsAndFree(CExtKeyAccount *sea);
    int ExtKeyLoadAccountPacks();

    int ExtKeyAppendToPack(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &idKey, CEKAKey &ak, bool &fUpdateAcc) const;
    int ExtKeyAppendToPack(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &idKey, CEKASCKey &asck, bool &fUpdateAcc) const;

    int ExtKeySaveKey(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &keyId, CEKAKey &ak) const;
    int ExtKeySaveKey(CExtKeyAccount *sea, const CKeyID &keyId, CEKAKey &ak) const;

    int ExtKeySaveKey(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &keyId, CEKASCKey &asck) const;
    int ExtKeySaveKey(CExtKeyAccount *sea, const CKeyID &keyId, CEKASCKey &asck) const;

    int ExtKeyUpdateStealthAddress(CHDWalletDB *pwdb, CExtKeyAccount *sea, CKeyID &sxId, std::string &sLabel);
    
    /**
     * Create an index db record for idKey
     */
    int ExtKeyNewIndex(CHDWalletDB *pwdb, const CKeyID &idKey, uint32_t &index);
    int ExtKeyGetIndex(CHDWalletDB *pwdb, CExtKeyAccount *sea, uint32_t &index, bool &fUpdate);

    int NewKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, CPubKey &pkOut, bool fInternal, bool fHardened, const char *plabel = NULL);
    int NewKeyFromAccount(CPubKey &pkOut, bool fInternal=false, bool fHardened=false, const char *plabel = NULL); // wrapper - use default account

    int NewStealthKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix);
    int NewStealthKeyFromAccount(std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix); // wrapper - use default account

    int NewExtKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, std::string &sLabel, CStoredExtKey *sekOut, const char *plabel = NULL, uint32_t *childNo=NULL);
    int NewExtKeyFromAccount(std::string &sLabel, CStoredExtKey *sekOut, const char *plabel = NULL, uint32_t *childNo=NULL); // wrapper - use default account

    int ExtKeyGetDestination(const CExtKeyPair &ek, CPubKey &pkDest, uint32_t &nKey);
    int ExtKeyUpdateLooseKey(const CExtKeyPair &ek, uint32_t nKey, bool fAddToAddressBook);
    
    int ScanChainFromTime(int64_t nTimeStartScan);
    int ScanChainFromHeight(int nHeight);
    
    bool CreateTransaction(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
                           std::string& strFailReason, const CCoinControl *coinControl = NULL, bool sign = true);
    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, CConnman* connman, CValidationState& state);
    
    int LoadStealthAddresses();
    bool UpdateStealthAddressIndex(const CKeyID &idK, const CStealthAddressIndexed &sxi, uint32_t &id); // Get stealth index or create new index if none found
    bool GetStealthLinked(const CKeyID &idK, CStealthAddress &sx);
    bool ProcessLockedStealthOutputs();
    bool ProcessStealthOutput(const CTxDestination &address,
        std::vector<uint8_t> &vchEphemPK, uint32_t prefix, bool fHavePrefix, CKey &sShared);
    bool FindStealthTransactions(const CTransaction &tx, mapValue_t &mapNarr);
    
    bool AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlockIndex* pIndex, int posInBlock, bool fUpdate);
    
    
    /**
     * populate vCoins with vector of available COutputs.
     */
    void AvailableCoins(std::vector<COutput>& vCoins, bool fOnlyConfirmed=true, const CCoinControl *coinControl = NULL, bool fIncludeZeroValue=false) const;
    
    bool SelectCoins(const std::vector<COutput>& vAvailableCoins, const CAmount& nTargetValue, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl *coinControl = NULL) const;
    
    void AvailableCoinsForStaking(std::vector<COutput> &vCoins, int64_t nTime, int nHeight);
    bool SelectCoinsForStaking(int64_t nTargetValue, int64_t nTime, int nHeight, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet);
    bool CreateCoinStake(unsigned int nBits, int64_t nTime, int nBlockHeight, int64_t nFees, CMutableTransaction &txNew, CKey &key);
    bool SignBlock(CBlockTemplate *pblocktemplate, int nHeight, int64_t nSearchTime);
    
    int64_t nLastCoinStakeSearchTime = 0;
    uint32_t nStealth, nFoundStealth; // for reporting, zero before use
    int64_t nReserveBalance;
    int deepestTxnDepth = 0; // for stake mining
    
    std::set<CStealthAddress> stealthAddresses;
    
    CStoredExtKey *pEKMaster;
    CKeyID idDefaultAccount;
    ExtKeyAccountMap mapExtAccounts;
    ExtKeyMap mapExtKeys;
    
    std::map<uint256, CTransactionRecord> mapRecords;
    
    std::vector<CVoteToken> vVoteTokens;
    
};

int ToStealthRecipient(CStealthAddress &sx, CAmount nValue, bool fSubtractFeeFromAmount,
    std::vector<CRecipient> &vecSend, std::string &sNarr, std::string &strError);

class LoopExtKeyCallback
{
public:
    // NOTE: the key and account instances passed to Process are temporary
    virtual int ProcessKey(CKeyID &id, CStoredExtKey &sek) {return 1;};
    virtual int ProcessAccount(CKeyID &id, CExtKeyAccount &sek) {return 1;};
};

int LoopExtKeysInDB(bool fInactive, bool fInAccount, LoopExtKeyCallback &callback);
int LoopExtAccountsInDB(bool fInactive, LoopExtKeyCallback &callback);

#endif // PARTICL_WALLET_HDWALLET_H
