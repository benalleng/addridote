# Addridote

Address poisoning is a form of phishing attack where an attacker creates vanity addresses with common beginning and final characters of their victim's address and then sends dust to thaat victim so that the last transaction in their transaction history is actually an address derived from the attacker.  The intent of this attack is that the wallet software hides the center part of the address or the user simply does not verify the entire address and copied an incorrect address when sending to an address they think they own.

Addridote is a minimal library to catch possible address poisoning attacks when sending to yourself, this is intended as a final catch for wallets to present errors to the user just before broadcasting.

Feature improvements

- [ ] utilizing wallet descriptors to check further address depth and not just inputs vs outputs

- [ ] severity for warning vs error
