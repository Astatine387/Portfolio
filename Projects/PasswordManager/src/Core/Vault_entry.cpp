/**
 * @file	Vault_entry.cpp
 * @brief	Implementation of entry management functions of Vault class
 * @author	Astatine387
 */

#include "Core/Vault.h"

int Vault::createEntry(const std::string &site, const std::string &acc, const Password &pw) {
	Entry newEntry = { site, acc, pw };

	auto res = entrySet.insert(newEntry);

	if (!res.second) {
		lastError = "[Entry] Insert failed - Entry already exists\n";
		return 1;
	}

	return 0;
}

int Vault::updateEntry(const std::string &oldSite, const std::string &oldAcc, 
					   const std::string &newSite, const std::string &newAcc, const Password &newPW) {
	/* Check whether the target entry exists */

	Entry oldEntry = { oldSite, oldAcc };

	auto oldIt = entrySet.find(oldEntry);

	if (oldIt == entrySet.end()) {
		lastError = "[Entry] Update failed - Original entry not found\n";
		return 1;
	}


	/* Check new entry data conflicts with existing entry */

	Entry newEntry = { newSite, newAcc, newPW };

	auto newIt = entrySet.find(newEntry);

	if (newIt != entrySet.end() && newIt != oldIt) {
		lastError = "[Entry] Update failed - Entry already exists\n";
		return 2;
	}

	entrySet.erase(oldIt);

	auto res = entrySet.insert(newEntry);

	if (!res.second) {
		lastError = "[Entry] Update failed - Cannot insert entry\n";
		return 1;
	}

	return 0;
}

int Vault::deleteEntry(const std::string &site, const std::string &acc) {
	Entry tar = { site, acc };

	auto it = entrySet.find(tar);

	if (it == entrySet.end()) {
		lastError = "[Entry] Delete failed - Entry not found\n";
		return 1;
	}

	entrySet.erase(it);

	return 0;
}