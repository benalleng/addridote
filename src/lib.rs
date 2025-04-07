use std::error::Error;

use bitcoin::{self, Address, AddressType, CompressedPublicKey, Network, Transaction};

fn min_match(address: Address) -> u8 {
    match address.address_type() {
        Some(AddressType::P2pkh) => 1u8,
        Some(AddressType::P2sh) => 1u8,
        Some(AddressType::P2wpkh) => 4u8,
        Some(AddressType::P2wsh) => 4u8,
        Some(AddressType::P2tr) => 4u8,
        Some(_) => 1u8,
        None => 1u8,
    }
}

pub fn checkaddr(transaction: Transaction) -> Result<(), Box<dyn Error>> {
    let network = Network::Bitcoin;
    let inputs = transaction.input;
    let outputs = transaction.output;
    let mut matches = 0;
    for (input, output) in inputs.iter().zip(outputs.iter()) {
        let output_address = Address::from_script(&output.script_pubkey, network).unwrap();
        let input_address = match output_address.address_type() {
            Some(AddressType::P2pkh) => {
                if !input.witness.is_empty() {
                    Address::p2pkh(
                        CompressedPublicKey::from_slice(&input.witness[1]).unwrap(),
                        network,
                    )
                } else {
                    Address::p2pkh(
                        CompressedPublicKey::from_slice(
                            input
                                .script_sig
                                .clone()
                                .as_mut_script()
                                .instructions()
                                .last()
                                .unwrap()
                                .unwrap()
                                .push_bytes()
                                .unwrap()
                                .as_bytes(),
                        )
                        .unwrap(),
                        network,
                    )
                }
            }
            Some(AddressType::P2sh) => Address::p2sh(&input.script_sig, network)?,
            Some(AddressType::P2wpkh) => {
                if !input.witness.is_empty() {
                    Address::p2wpkh(
                        &CompressedPublicKey::from_slice(&input.witness[1]).unwrap(),
                        network,
                    )
                } else {
                    Address::p2wpkh(
                        &CompressedPublicKey::from_slice(
                            input
                                .script_sig
                                .clone()
                                .as_mut_script()
                                .instructions()
                                .last()
                                .unwrap()
                                .unwrap()
                                .push_bytes()
                                .unwrap()
                                .as_bytes(),
                        )
                        .unwrap(),
                        network,
                    )
                }
            }
            Some(AddressType::P2wsh) => Address::p2wsh(&input.script_sig, network),
            _ => panic!("Unmatched address type"),
        };
        for (i, (addr_in_char, addr_out_char)) in input_address
            .to_string()
            .chars()
            .zip(output_address.to_string().chars())
            .enumerate()
        {
            if addr_in_char == addr_out_char && i >= min_match(input_address.clone()) as usize {
                matches += 1;
            }
        }

        if matches < min_match(input_address.clone()) {
            return Ok(());
        } else if matches > min_match(input_address.clone())
            && matches < min_match(input_address.clone()) + 4
        {
            return Err("There are some matches, this is likely a poisoned address".into());
        } else if matches > min_match(input_address.clone()) + 4 {
            return Err("There are too many matches, this is definitely a poisoned address".into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use bitcoin::{consensus::Decodable, Transaction};

    use crate::checkaddr;
    use core::panic;
    use std::error::Error;

    #[test]
    fn check_p2wpkh() -> Result<(), Box<dyn Error>> {
        let raw_tx = hex::decode("01000000000101305cebd33c480197fb8a811a17c5e31b0cc2aa198ccebf74d5e6243f39c69f7e0000000000ffffffff014a01000000000000160014f28eb5933d37c2e77b0406ae8b8fb7d9826f78b60247304402207a957542c7583ef0c47f2e74abc7fc0c71417ef8ec6f5e33835653e828452fce0220330ece68245842194b71d5632e62c5bf39d81fe716118a59182319a821760f0301210359c3dbc04edd9aa05d07de2eac54ba5b35c7180726d7c55b8ff53a5a569252d200000000").unwrap();
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        let checked_addr = checkaddr(tx);
        match checked_addr {
            Ok(_) => panic!("This tx has a poisoned address and should error"),
            Err(e) => {
                println!("Error: {}", e);
            }
        }

        Ok(())
    }

    #[test]
    fn check_p2pkh() -> Result<(), Box<dyn Error>> {
        let raw_tx = hex::decode("0100000001305cebd33c480197fb8a811a17c5e31b0cc2aa198ccebf74d5e6243f39c69f7e1a0000006b483045022100c7f32ada49b6ac3671df199b340e99ee265f4bf2b55f0ff42f1d81fcfff2b89202206db77245cca5306dc45ae53c3b8767664ca6d59564f187bee7e36d8e574d525c0121022f01afe08a6d96ae27fdbaa456887491c6216e118bbb7108826cd48f7b03eee3ffffffff0158020000000000001976a9147adbfd4dd9b4f943377c4c3edb59ca23d8570dd388ac00000000").unwrap();
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        let checked_addr = checkaddr(tx);
        match checked_addr {
            Ok(_) => panic!("This tx has a poisoned address and should error"),
            Err(e) => {
                println!("Error: {}", e);
            }
        }

        Ok(())
    }

    #[test]
    fn check_p2sh() -> Result<(), Box<dyn Error>> {
        let raw_tx = hex::decode("01000000000101305cebd33c480197fb8a811a17c5e31b0cc2aa198ccebf74d5e6243f39c69f7e6b00000017160014530b380fb9a2e88480def4b91ec71a80868b24e7ffffffff01580200000000000017a914d1c4944c1630fe08ce8fe2b158a40cdee157a79b870247304402207834cddef78cafb714c52d648564bf444144f5f5dfa3cab209a6d79107a8987602207326f31870dfaaddaa834641e06021e70431ec8df4eb47226bcf94196ea41291012103beccce5251171541d6daca27a2a5cef3cfd7e91d6c3963026b1432e258ee368b00000000").unwrap();
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        let checked_addr = checkaddr(tx);
        match checked_addr {
            Ok(_) => panic!("This tx has a poisoned address and should error"),
            Err(e) => {
                println!("Error: {}", e);
            }
        }

        Ok(())
    }

    #[test]
    fn check_safe() -> Result<(), Box<dyn Error>> {
        let raw_tx = hex::decode("01000000018302638ddd19b1a3ae924fabb40dd9c810c6a48df03068cb6c4d163a75c40593010000006a4730440220410e1cb7379104a925826fb5d517d4e77b9f7be2461bbec2bc5e61fb45ea74090220712aebb67dbf22b1635fea8f2b8d0f4d1ad3403a9e3fd152ea30411402297ccd01210290104861416d1be53eaecb7954447c9331716e73d12e92d8b49aa863092b80f2ffffffff020676010000000000160014fe0a35a0dfd485c208d14587bd5d0a0073c3e1f078060600000000001976a914acfddff620635c3285beaac727d25311bc20088488ac00000000").unwrap();
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        let checked_addr = checkaddr(tx);
        match checked_addr {
            Ok(_) => assert!(checked_addr.is_ok()),
            Err(e) => {
                panic!(
                    "This tx has no matching addresses and should return ok but got error: {}",
                    e
                )
            }
        }
        Ok(())
    }
}
