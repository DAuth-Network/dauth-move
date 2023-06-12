module dauth::verify {
    use std::vector;
    use std::option;
    use aptos_std::secp256k1;

    use dauth::node_register;

    #[view]
    public fun verify(v: u8, r: vector<u8>, s: vector<u8>, message_hash: vector<u8>, node_number: u64): bool {
        v = if (v == 0 || v == 27) 0 else 1;

        let node_pubkey = node_register::get_node_pubkey(node_number);

        let signature = vector::empty<u8>();

        let i = 0;
        while (i < 32) {
            vector::push_back(&mut signature, *vector::borrow(&r, i));
            i = i + 1;
        };
        i = 0;
        while (i < 32) {
            vector::push_back(&mut signature, *vector::borrow(&s, i));
            i = i + 1;
        };

        let optionalPubKey = secp256k1::ecdsa_recover(message_hash, v, &secp256k1::ecdsa_signature_from_bytes(signature));

        option::is_some(&optionalPubKey) && secp256k1::ecdsa_raw_public_key_to_bytes(option::borrow(&optionalPubKey)) == node_pubkey
    }

    // https://paulmillr.com/noble/
    // https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-stdlib/sources/cryptography/secp256k1.move#L83
    // privatekey:     b5695cf8f07cbb7e1660d53c4787aa73a859950ed5847ddece332459fe98685e
    // pubkey:         975276b14dde2728cb1a55f75beb08434fcdd0f5f08f97a6a6b9a13b9877b41925a5d78ea0c51a1c8d9b616b897d254503f606af599e31a9ff0f9a600bdee5e4
    // message:        hello dauth
    // sha256 hash:    b14293392e984cbd274c72dd3614a3b6344b2634e4694fcb508f2848af17fd21
    // r:              5c8bef03c016dd130a7431144d4e4fa056f57ed7ecde1fabfb321bdeac29df02
    // s:              34bb7feb0f9da8f801f84dd9ca3b7eb941b1494bd6310af03d97b13eaf2a0aac
    // v:              28
    //
    // @nodejs
    // import util from 'ethereumjs-util'
    // const privateKey = Buffer.from('b5695cf8f07cbb7e1660d53c4787aa73a859950ed5847ddece332459fe98685e', 'hex')
    // console.log('privateKey', privateKey.toString('hex'))
    // console.log('publicKey', util.privateToPublic(privateKey).toString('hex'))
    // const message = 'hello dauth'
    // console.log('message', message)
    // const messageHash = util.sha256(Buffer.from(message))
    // console.log('message sha256 hash', messageHash.toString('hex'))
    // const signature = util.ecsign(messageHash, privateKey)
    // console.log('r', signature.r.toString('hex'))
    // console.log('s', signature.s.toString('hex'))
    // console.log('v', signature.v)
    #[test(account = @dauth)]
    fun test_verify(account: &signer) {
        use std::hash;

        node_register::test_init_module(account);
        node_register::register(account, vector::empty<u8>(), x"975276b14dde2728cb1a55f75beb08434fcdd0f5f08f97a6a6b9a13b9877b41925a5d78ea0c51a1c8d9b616b897d254503f606af599e31a9ff0f9a600bdee5e4");

        let message_hash = hash::sha2_256(b"hello dauth");
        let r = x"5c8bef03c016dd130a7431144d4e4fa056f57ed7ecde1fabfb321bdeac29df02";
        let s = x"34bb7feb0f9da8f801f84dd9ca3b7eb941b1494bd6310af03d97b13eaf2a0aac";
        let v: u8 = 28;
        assert!(verify(v, r, s, message_hash, 0), 0);
    }
}