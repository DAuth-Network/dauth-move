module dauth::node_register {
    use std::signer;
    use std::vector;

    const E_NOT_OWNER: u64 = 1;

    struct Owner has key {
        owner: address
    }

    struct RegisteredNode has key {
        nodes: vector<vector<u8>>
    }

    fun init_module(account: &signer) {
        move_to(account, Owner { owner: signer::address_of(account) });
        move_to(account, RegisteredNode { nodes: vector::empty<vector<u8>>() });
    }

    public entry fun register(sender: &signer, proof: vector<u8>, node_pubkey: vector<u8>) acquires Owner, RegisteredNode {
        assert!(borrow_global<Owner>(@dauth).owner == signer::address_of(sender), E_NOT_OWNER);

        if (verifyProof(proof)) {
            vector::push_back(&mut borrow_global_mut<RegisteredNode>(@dauth).nodes, node_pubkey);
        }
    }

    #[view]
    public fun get_node_pubkey(node_number: u64): vector<u8> acquires RegisteredNode {
        let nodes = borrow_global<RegisteredNode>(@dauth).nodes;
        if (node_number < vector::length(&nodes)) *vector::borrow(&nodes, node_number) else vector::empty<u8>()
    }

    fun verifyProof(_proof: vector<u8>): bool {
        true
    }

    #[test_only]
    public fun test_init_module(account: &signer) {
        init_module(account);
    }

    #[test(account = @dauth)]
    fun test_owner(account: &signer) acquires Owner {
        init_module(account);

        assert!(borrow_global<Owner>(@dauth).owner == @dauth, 0);
    }

    #[test(account = @dauth, sender = @0xa11ce), expected_failure(abort_code = E_NOT_OWNER)]
    fun test_not_owner(account: &signer, sender: &signer) acquires Owner, RegisteredNode {
        init_module(account);

        register(sender, vector::empty<u8>(), vector::empty<u8>());
    }

    #[test(account = @dauth)]
    fun test_basic_flow(account: &signer) acquires Owner, RegisteredNode {
        init_module(account);

        let node_pubkey = x"a11ce0";
        register(account, vector::empty<u8>(), node_pubkey);
        assert!(get_node_pubkey(0) == node_pubkey, 0);
        assert!(vector::length(&get_node_pubkey(1)) == 0, 0);
    }
}
