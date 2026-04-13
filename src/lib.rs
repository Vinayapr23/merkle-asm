#[cfg(test)]
mod tests {
    use mollusk_svm::{result::Check, Mollusk};
    use solana_account::Account;
    use solana_address::Address;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_program_error::ProgramError;
    use sha2::{Digest, Sha256};

    const MAX_DATA: usize = 10240;
    const TREE_SIZE: usize = 712;
    const DEPTH: usize = 20;

    fn get_program_id() -> Address {
        let bytes = std::fs::read("deploy/merkle-asm-keypair.json")
            .unwrap()[..32]
            .try_into()
            .expect("slice with incorrect length");
        Address::new_from_array(bytes)
    }

    fn new_mollusk() -> Mollusk {
        Mollusk::new(&get_program_id(), "deploy/merkle-asm")
    }

    fn zero_hashes() -> Vec<[u8; 32]> {
        let mut h: Vec<[u8; 32]> = Vec::with_capacity(21);
        let mut cur: [u8; 32] = Sha256::digest([0u8; 32]).into();
        h.push(cur);
        for _ in 1..=20 {
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(&cur);
            input[32..].copy_from_slice(&cur);
            cur = Sha256::digest(input).into();
            h.push(cur);
        }
        h
    }

    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(left);
        h.update(right);
        h.finalize().into()
    }
    fn empty_tree_account(program_id: &Address) -> Account {
        Account {
            data: vec![0u8; MAX_DATA],
            lamports: 1_000_000,
            owner: *program_id,
            ..Default::default()
        }
    }

    fn make_tree_account(
        program_id: &Address,
        authority: &Address,
        bump: u8,
        next_index: u32,
        root: Option<[u8; 32]>,
    ) -> Account {
        let zh = zero_hashes();
        let mut data = vec![0u8; MAX_DATA];
        data[0..32].copy_from_slice(&authority.to_bytes());
        data[0x20] = 20;
        data[0x21] = bump;
        data[0x24..0x28].copy_from_slice(&next_index.to_le_bytes());
        let r = root.unwrap_or(zh[20]);
        data[0x28..0x48].copy_from_slice(&r);
        for i in 0..DEPTH {
            let off = 0x48 + i * 32;
            data[off..off + 32].copy_from_slice(&zh[i]);
        }
        Account {
            data,
            lamports: 1_000_000,
            owner: *program_id,
            ..Default::default()
        }
    }


    fn authority_account() -> Account {
        Account {
            data: vec![0u8; MAX_DATA],
            lamports: 1_000_000_000,
            owner: Address::default(),
            ..Default::default()
        }
    }

    #[test]
    fn test_initialize() {
        let program_id = get_program_id();
        let mollusk = new_mollusk();
        let zh = zero_hashes();

        let authority = Address::new_unique();
        let (tree_pda, bump) =
            Address::find_program_address(&[b"merkle", &authority.to_bytes()], &program_id);

        let ix = Instruction::new_with_bytes(
            program_id,
            &[0u8, bump],
            vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(tree_pda, false),
            ],
        );

        let result = mollusk.process_and_validate_instruction(
            &ix,
            &[
                (authority, authority_account()),
                (tree_pda, empty_tree_account(&program_id)),
            ],
            &[Check::success()],
        );
        println!("initialize CU: {}", result.compute_units_consumed);
        let data = &result.resulting_accounts[1].1.data;
        assert_eq!(data[0x20], 20, "depth");
        assert_eq!(data[0x21], bump, "bump");
        let ni = u32::from_le_bytes(data[0x24..0x28].try_into().unwrap());
        assert_eq!(ni, 0, "next_index");
        assert_eq!(&data[0x28..0x48], &zh[20], "root = ZERO_HASHES[20]");

    }

    #[test]
    fn test_insert_single_leaf() {
        let program_id = get_program_id();
        let mollusk = new_mollusk();
        let zh = zero_hashes();

        let authority = Address::new_unique();
        let (tree_pda, bump) =
            Address::find_program_address(&[b"merkle", &authority.to_bytes()], &program_id);
        let tree_acct = make_tree_account(&program_id, &authority, bump, 0, None);

        let leaf = [1u8; 32];
        let mut ix_data = vec![1u8];
        ix_data.extend_from_slice(&leaf);

        let ix = Instruction::new_with_bytes(
            program_id,
            &ix_data,
            vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(tree_pda, false),
            ],
        );

        let result = mollusk.process_and_validate_instruction(
            &ix,
            &[(authority, authority_account()), (tree_pda, tree_acct)],
            &[Check::success()],
        );

        println!("insert CU: {}", result.compute_units_consumed);

        let data = &result.resulting_accounts[1].1.data;
        let ni = u32::from_le_bytes(data[0x24..0x28].try_into().unwrap());
        assert_eq!(ni, 1, "next_index should be 1");

        let mut expected = leaf;
        for i in 0..DEPTH {
            expected = hash_pair(&expected, &zh[i]);
        }
        let actual: [u8; 32] = data[0x28..0x48].try_into().unwrap();
        assert_eq!(actual, expected, "root mismatch");

    }

    #[test]
    fn test_verify_single_leaf() {
        let program_id = get_program_id();
        let mollusk = new_mollusk();
        let zh = zero_hashes();

        let authority = Address::new_unique();
        let (tree_pda, bump) =
            Address::find_program_address(&[b"merkle", &authority.to_bytes()], &program_id);

        let leaf = [1u8; 32];
        let mut root = leaf;
        for i in 0..DEPTH {
            root = hash_pair(&root, &zh[i]);
        }
        let tree_acct = make_tree_account(&program_id, &authority, bump, 1, Some(root));

        let mut proof = [0u8; 640];
        for i in 0..DEPTH {
            proof[i * 32..(i + 1) * 32].copy_from_slice(&zh[i]);
        }

        let mut ix_data = vec![2u8];
        ix_data.extend_from_slice(&leaf);
        ix_data.extend_from_slice(&0u32.to_le_bytes());
        ix_data.extend_from_slice(&proof);

        let ix = Instruction::new_with_bytes(
            program_id,
            &ix_data,
            vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(tree_pda, false),
            ],
        );

       let result = mollusk.process_and_validate_instruction(
            &ix,
            &[(authority, authority_account()), (tree_pda, tree_acct)],
            &[Check::success()],
        );
        println!(" verify CU: {}", result.compute_units_consumed);

    
    }

    #[test]
    fn test_verify_wrong_proof_fails() {
        let program_id = get_program_id();
        let mollusk = new_mollusk();
        let zh = zero_hashes();

        let authority = Address::new_unique();
        let (tree_pda, bump) =
            Address::find_program_address(&[b"merkle", &authority.to_bytes()], &program_id);

        let leaf = [1u8; 32];
        let mut root = leaf;
        for i in 0..DEPTH {
            root = hash_pair(&root, &zh[i]);
        }
        let tree_acct = make_tree_account(&program_id, &authority, bump, 1, Some(root));

        let mut ix_data = vec![2u8];
        ix_data.extend_from_slice(&leaf);
        ix_data.extend_from_slice(&0u32.to_le_bytes());
        ix_data.extend_from_slice(&[0u8; 640]); // wrong proof

        let ix = Instruction::new_with_bytes(
            program_id,
            &ix_data,
            vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(tree_pda, false),
            ],
        );

        mollusk.process_and_validate_instruction(
            &ix,
            &[(authority, authority_account()), (tree_pda, tree_acct)],
            &[Check::err(ProgramError::Custom(0x09))],
        );

    }

    #[test]
    fn test_insert_zero_leaf_fails() {
        let program_id = get_program_id();
        let mollusk = new_mollusk();

        let authority = Address::new_unique();
        let (tree_pda, bump) =
            Address::find_program_address(&[b"merkle", &authority.to_bytes()], &program_id);
        let tree_acct = make_tree_account(&program_id, &authority, bump, 0, None);

        let mut ix_data = vec![1u8];
        ix_data.extend_from_slice(&[0u8; 32]);

        let ix = Instruction::new_with_bytes(
            program_id,
            &ix_data,
            vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(tree_pda, false),
            ],
        );

        mollusk.process_and_validate_instruction(
            &ix,
            &[(authority, authority_account()), (tree_pda, tree_acct)],
            &[Check::err(ProgramError::Custom(0x08))],
        );
       
    }

    #[test]
    fn test_wrong_authority_fails() {
        let program_id = get_program_id();
        let mollusk = new_mollusk();

        let authority = Address::new_unique();
        let wrong = Address::new_unique();

        let (tree_pda, bump) =
            Address::find_program_address(&[b"merkle", &authority.to_bytes()], &program_id);
        let tree_acct = make_tree_account(&program_id, &authority, bump, 0, None);

        let mut ix_data = vec![1u8];
        ix_data.extend_from_slice(&[1u8; 32]);

        let ix = Instruction::new_with_bytes(
            program_id,
            &ix_data,
            vec![
                AccountMeta::new(wrong, true),
                AccountMeta::new(tree_pda, false),
            ],
        );

        mollusk.process_and_validate_instruction(
            &ix,
            &[(wrong, authority_account()), (tree_pda, tree_acct)],
            &[Check::err(ProgramError::Custom(0x06))],
        );
    
    }
}