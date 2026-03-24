/**
 * @file	Vault.h
 * @brief	Manages password vaults
 * @author	Astatine387
 */

#pragma once

#include "Common/constants.h"
#include "Core/AES_GCM.h"
#include "Core/Entry.h"
#include <QString>
#include <functional>
#include <memory>
#include <set>
#include <string>

/**
 * @class	Vault
 * @brief	Manages password vaults
 */
class Vault {
public:
	/* ==================================================
	 * Constructor and Destructor
	 * ================================================== */

	/**
	 * @brief	Default constructor of Vault class
	 */
	Vault();

	/**
	 * @brief	Default destructor of Vault class
	 */
	~Vault();


	/* ==================================================
	 * Vault file functions
	 * ================================================== */

	/**
	 * @brief	Create an empty new vault
	 * @param   path    Vault file path
	 * @return  0 on success, 1 on failure
	 */
	int newVault(const QString &path);

	/**
	 * @brief	Open a vault and read its data
	 * @param   path    Vault file path
	 * @return  0 on success, 1 on failure
	 */
	int openVault(const QString &path);

	/**
	 * @brief	Save the current vault
	 * @param   path    Vault file path
	 * @return	0 on success, 1 on failure
	 */
	int saveVault(const QString &path);

	/**
	 * @brief	Close the vault and wipe all data
	 */
	void closeVault();


	/* ==================================================
	 * Vault password functions
	 * ================================================== */

	/**
	 * @brief	Verify the master password
	 * @param	curPW	Password to verify
	 * @return	true if password is correct
	 */
	bool verifyPW(const Password &curPW) const;

	/**
	 * @brief	Change the master password and re-encrypt vault
	 * @param	newPW	New password
	 * @param	path	Vault file path
	 * @return	0 on success, 1 on save failure
	 */
	int changePW(const Password &newPW, const QString &path);

	/**
	 * @brief	Set the master password of vault
	 * @param	pw	Master password
	 */
	void setPW(const Password &pw);


	/* ==================================================
	 * Entry CRUD functions
	 * ================================================== */

	/**
	 * @brief	Create a new entry
	 * @param	site	Site name of the new entry
	 * @param	acc		Account of the new entry
	 * @param	pw		Password of the new entry
	 * @return	0 on success, 1 on failure
	 */
	int createEntry(const std::string &site, const std::string &acc, const Password &pw);

	/**
	 * @brief	Update an entry
	 * @param	oldSite		Site name of the target entry
	 * @param	oldAcc		Account of the target entry
	 * @param	newSite		New site name
	 * @param	newAcc		New account
	 * @param	newPw		New password
	 * @return	0 on success, 1 on failure
	 */
	int updateEntry(const std::string &oldSite, const std::string &oldAcc, 
					const std::string &newSite, const std::string &newAcc, const Password &newPW);

	/**
	 * @brief	Delete an entry
	 * @param	site	Site name of the target entry
	 * @param	acc		Account of the target entry
	 * @return	0 on success, 1 on failure
	 */
	int deleteEntry(const std::string &site, const std::string &acc);


	/* ==================================================
	 * Accessor functions
	 * ================================================== */

	/**
	 * @brief	Get a reference to the entry set
	 * @return	Reference to the entry set
	 */
	const std::set<Entry, EntryCmp> &getEntries() const;

	/**
	 * @brief	Get the number of entries
	 * @return	Number of entries
	 */
	int getEntryCount() const;


	/* ==================================================
	 * Callback functions
	 * ================================================== */

	/**
	 * @brief	Callback function for error reporting
	 * @param	errMsg	Error message string
	 */
	using ErrorCallback = std::function<void(const char *errMsg)>;

	/**
	 * @brief	Set error callback function
	 * @param	ecb		Error callback function
	 */
	void setErrorCb(ErrorCallback ecb) {
		this->ecb = ecb;
	}

	/**
	 * @brief	Get the last error message
	 * @return	Last error message
	 */
	const std::string &getLastError() const;

private:
	AES_GCM aes;
	Password pw;
	std::set<Entry, EntryCmp> entrySet;
	std::string lastError;

	ErrorCallback ecb = nullptr;

	FILE *file = nullptr;
	std::unique_ptr<uint8_t[]> srcBuff;
	std::unique_ptr<uint8_t[]> dstBuff;
	int64_t srcSize = 0, dstSize = 0;
	uint32_t magicNum = kMagicNum;


	/* ==================================================
	 * Helper functions
	 * ================================================== */

	void clear();


	/* ==================================================
	 * Callback helper functions
	 * ================================================== */

	/**
	  * @brief	Report error via callback
	  * @param	msg		Error message string
	  */
	void reportError(const char *msg);
};