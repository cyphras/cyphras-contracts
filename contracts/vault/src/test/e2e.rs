//! The real-proof flow: two shields, their admission, a relayed transfer, a relayed unshield to a
//! muxed address, a self-relayed unshield to a contract and a zero-value transaction, every proof
//! made by snarkjs with the testnet-forgeable key and verified with the embedded key.

use serde_json::Value;
use soroban_sdk::{
    crypto::bn254::Bn254Fr, testutils::Events as _, xdr::ToXdr, Address, Bytes, Event,
    MuxedAddress, U256,
};
use types::TxProof;
use verifier::VerifyingKey;

use super::{
    exits::to_midnight,
    fixtures,
    setup::{create_account, limits, outcome, Setup, DELAY_SMALL, XLM},
};
use crate::{events, Error, Limits};

pub struct Flow {
    pub s: Setup,
    pub alice: Address,
    pub bob: Address,
    pub relayer: Address,
    pub exchange: Address,
    pub merchant: Address,
}

impl Flow {
    pub fn new() -> Self {
        Self::with_limits(limits())
    }

    pub fn with_limits(limits: Limits) -> Self {
        let s = Setup::real_with_limits(limits);
        let env = &s.env;
        let account = |name: &str, balance: i128| {
            let address = fixtures::account(env, name);
            create_account(env, &address, balance);
            address
        };
        Flow {
            alice: account("alice", 2_000 * XLM),
            bob: account("bob", 2_000 * XLM),
            relayer: account("relayer", 0),
            exchange: account("exchange", 0),
            merchant: fixtures::account(env, "merchant"),
            s,
        }
    }

    /// A flow advanced to just before the named step.
    pub fn at(step: &str) -> Self {
        let flow = Flow::new();
        flow.run_until(step);
        flow
    }

    pub fn run_until(&self, step: &str) {
        for s in fixtures::proofs()["steps"].as_array().unwrap() {
            if s["name"] == step {
                return;
            }
            self.run(s).unwrap();
        }
        panic!("no fixture step {step}");
    }

    pub fn caller(&self, step: &Value) -> Address {
        Address::from_str(&self.s.env, step["caller"].as_str().unwrap())
    }

    pub fn run(&self, step: &Value) -> Result<(), Error> {
        let env = &self.s.env;
        let vault = &self.s.vault;
        match step["call"].as_str().unwrap() {
            "admit" => {
                let ids: std::vec::Vec<u64> = step["ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| id.as_u64().unwrap())
                    .collect();
                vault.attest(ids.last().unwrap());
                self.s.advance(DELAY_SMALL);
                let ids = soroban_sdk::Vec::from_slice(env, &ids);
                assert_eq!(vault.admit(&ids), ids);
                Ok(())
            }
            call => {
                let ext = fixtures::ext(env, step);
                let proof = fixtures::proof(env, step);
                let caller = self.caller(step);
                if call == "shield" {
                    outcome(vault.try_shield(&proof, &ext, &caller)).map(|_| ())
                } else {
                    outcome(vault.try_transact(&proof, &ext, &caller))
                }
            }
        }
    }
}

fn root_after(flow: &Flow, step: &Value) -> U256 {
    fixtures::field(&flow.s.env, &step["root_after"])
}

#[test]
fn real_proofs_move_value_through_every_kind_of_transaction() {
    let flow = Flow::new();
    let s = &flow.s;
    let env = &s.env;
    let vault = s.vault.address.clone();
    let proofs = fixtures::proofs();
    assert_eq!(
        s.vault.config().domain,
        fixtures::field(env, &proofs["domain"])
    );
    assert_eq!(
        s.vault.current_root(),
        fixtures::field(env, &proofs["empty_root"])
    );

    let step = fixtures::step("shield_alice");
    flow.run(&step).unwrap();
    let step = fixtures::step("shield_bob");
    flow.run(&step).unwrap();
    assert_eq!(s.balance(&vault), 1_500_000_000);
    assert_eq!(s.balance(&flow.alice), 2_000 * XLM - 1_000_000_000);
    assert_eq!(s.balance(&flow.bob), 2_000 * XLM - 500_000_000);
    assert_eq!(s.vault.status().tvl, 1_500_000_000);
    assert_eq!(s.vault.pending(&2).unwrap().depositor, flow.bob);
    assert_eq!(s.vault.next_leaf_index(), 0);

    let step = fixtures::step("admit");
    flow.run(&step).unwrap();
    assert_eq!(s.vault.current_root(), root_after(&flow, &step));
    assert_eq!(s.vault.next_leaf_index(), 4);
    assert!(s.vault.pending(&1).is_none() && s.vault.pending(&2).is_none());

    let step = fixtures::step("transfer");
    flow.run(&step).unwrap();
    assert_eq!(s.vault.current_root(), root_after(&flow, &step));
    assert_eq!(s.balance(&flow.relayer), 5_000_000);
    assert_eq!(s.vault.status().tvl, 1_495_000_000);

    let step = fixtures::step("unshield_muxed");
    flow.run(&step).unwrap();
    assert_eq!(s.vault.current_root(), root_after(&flow, &step));
    assert_eq!(s.balance(&flow.exchange), 700_000_000);
    assert_eq!(s.balance(&flow.relayer), 15_000_000);

    let step = fixtures::step("unshield_self");
    flow.run(&step).unwrap();
    assert_eq!(s.vault.current_root(), root_after(&flow, &step));
    assert_eq!(s.balance(&flow.merchant), 695_000_000);

    let step = fixtures::step("zero_value");
    flow.run(&step).unwrap();
    assert_eq!(s.vault.current_root(), root_after(&flow, &step));
    assert_eq!(s.vault.next_leaf_index(), 12);
    assert_eq!(s.vault.status().tvl, 90_000_000);
    assert_eq!(s.balance(&vault), 90_000_000);

    for step in proofs["steps"].as_array().unwrap() {
        if step["call"] != "admit" {
            for nf in step["proof"]["input_nullifiers"].as_array().unwrap() {
                assert!(s.vault.is_spent(&fixtures::field(env, nf)));
            }
        }
    }
}

#[test]
fn the_ext_data_encoding_matches_the_reference() {
    let s = Setup::real();
    let env = &s.env;
    for step in fixtures::proofs()["steps"].as_array().unwrap() {
        if step["call"] == "admit" {
            continue;
        }
        let ext = fixtures::ext(env, step);
        let xdr = Bytes::from_slice(env, &fixtures::raw(step["ext_xdr"].as_str().unwrap()));
        assert_eq!(ext.clone().to_xdr(env), xdr, "{}", step["name"]);
        assert_eq!(
            crate::proof::ext_data_hash(env, &ext),
            fixtures::field(env, &step["proof"]["ext_data_hash"])
        );
    }
}

#[test]
fn a_shield_emits_its_nullifiers_then_the_pending_deposit() {
    let flow = Flow::new();
    let s = &flow.s;
    let env = &s.env;
    let step = fixtures::step("shield_alice");
    let proof = fixtures::proof(env, &step);
    flow.run(&step).unwrap();

    let nf = |i| proof.input_nullifiers.get_unchecked(i);
    let cm = |i| proof.output_commitments.get_unchecked(i);
    let vault = s.vault.address.clone();
    assert_eq!(
        env.events().all().filter_by_contract(&vault),
        std::vec![
            events::NewNullifier { nullifier: nf(0) }.to_xdr(env, &vault),
            events::NewNullifier { nullifier: nf(1) }.to_xdr(env, &vault),
            events::DepositPending {
                id: 1,
                depositor: flow.alice.clone(),
                amount: 1_000_000_000,
                commitment0: cm(0),
                commitment1: cm(1),
                created_at: s.now(),
            }
            .to_xdr(env, &vault),
        ]
    );
}

#[test]
fn an_admission_emits_both_commitments_with_their_ciphertexts() {
    let flow = Flow::at("admit");
    let s = &flow.s;
    let env = &s.env;
    let alice = fixtures::ext(env, &fixtures::step("shield_alice"));
    let alice_cm = fixtures::proof(env, &fixtures::step("shield_alice")).output_commitments;
    let bob = fixtures::ext(env, &fixtures::step("shield_bob"));
    let bob_cm = fixtures::proof(env, &fixtures::step("shield_bob")).output_commitments;
    flow.run(&fixtures::step("admit")).unwrap();

    let vault = s.vault.address.clone();
    let commitment = |index, commitment, encrypted_output| {
        events::NewCommitment {
            index,
            commitment,
            encrypted_output,
        }
        .to_xdr(env, &vault)
    };
    assert_eq!(
        env.events().all().filter_by_contract(&vault),
        std::vec![
            commitment(0, alice_cm.get_unchecked(0), alice.encrypted_output0),
            commitment(1, alice_cm.get_unchecked(1), alice.encrypted_output1),
            events::DepositAdmitted {
                id: 1,
                leaf_index0: 0,
                leaf_index1: 1
            }
            .to_xdr(env, &vault),
            commitment(2, bob_cm.get_unchecked(0), bob.encrypted_output0),
            commitment(3, bob_cm.get_unchecked(1), bob.encrypted_output1),
            events::DepositAdmitted {
                id: 2,
                leaf_index0: 2,
                leaf_index1: 3
            }
            .to_xdr(env, &vault),
        ]
    );
}

#[test]
fn an_unshield_to_a_muxed_address_pays_its_base_account_and_reports_the_muxed_id() {
    let flow = Flow::at("unshield_muxed");
    let s = &flow.s;
    let env = &s.env;
    let step = fixtures::step("unshield_muxed");
    let ext = fixtures::ext(env, &step);
    let proof = fixtures::proof(env, &step);
    assert_eq!(ext.recipient.id(), Some(1_234_567_890_123));
    assert_eq!(ext.recipient.address(), flow.exchange);
    flow.run(&step).unwrap();

    let vault = s.vault.address.clone();
    let all = env.events().all();
    let ours = all.filter_by_contract(&vault);
    let nf = |i| proof.input_nullifiers.get_unchecked(i);
    let cm = |i| proof.output_commitments.get_unchecked(i);
    assert_eq!(
        ours,
        std::vec![
            events::NewNullifier { nullifier: nf(0) }.to_xdr(env, &vault),
            events::NewNullifier { nullifier: nf(1) }.to_xdr(env, &vault),
            events::NewCommitment {
                index: 6,
                commitment: cm(0),
                encrypted_output: ext.encrypted_output0.clone()
            }
            .to_xdr(env, &vault),
            events::NewCommitment {
                index: 7,
                commitment: cm(1),
                encrypted_output: ext.encrypted_output1.clone()
            }
            .to_xdr(env, &vault),
            events::Settled {
                ext_amount: -700_000_000,
                fee: 10_000_000,
                recipient: MuxedAddress::from_str(
                    env,
                    fixtures::proofs()["accounts"]["exchange_muxed"]
                        .as_str()
                        .unwrap()
                ),
                relayer: flow.relayer.clone(),
                exit_id: None,
            }
            .to_xdr(env, &vault),
        ]
    );
    // The asset contract's own events carry the payout and the fee, in that order.
    let transfers = all.filter_by_contract(&s.token.address);
    assert_eq!(transfers.events().len(), 2);
    assert_eq!(s.balance(&flow.exchange), 700_000_000);
    assert_eq!(s.balance(&flow.relayer), 15_000_000);
    assert_eq!(
        s.vault.status().outflow,
        5_000_000 + 700_000_000 + 10_000_000
    );
}

#[test]
fn a_real_proof_exit_that_does_not_fit_waits_and_is_released_under_its_id() {
    // A window too small for the transfer's fee and the muxed unshield on the same day.
    let window = 710_000_000;
    let flow = Flow::with_limits(Limits {
        max_daily_outflow: window,
        tvl_cap: 7 * window,
        ..limits()
    });
    let s = &flow.s;
    let env = &s.env;
    flow.run_until("unshield_muxed");
    let step = fixtures::step("unshield_muxed");
    let ext = fixtures::ext(env, &step);
    flow.run(&step).unwrap();

    let vault = s.vault.address.clone();
    let queued = events::ExitQueued {
        id: 1,
        ext_amount: -700_000_000,
        fee: 10_000_000,
        recipient: ext.recipient.clone(),
        relayer: flow.relayer.clone(),
    };
    let all = env.events().all();
    assert_eq!(
        all.filter_by_contract(&vault).events().last(),
        Some(&queued.to_xdr(env, &vault))
    );
    assert!(all.filter_by_contract(&s.token.address).events().is_empty());
    assert_eq!(s.vault.current_root(), root_after(&flow, &step));
    assert_eq!(s.balance(&flow.exchange), 0);

    to_midnight(s);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(
        env.events().all().filter_by_contract(&vault),
        std::vec![events::Settled {
            ext_amount: -700_000_000,
            fee: 10_000_000,
            recipient: ext.recipient,
            relayer: flow.relayer.clone(),
            exit_id: Some(1),
        }
        .to_xdr(env, &vault)]
    );
    assert_eq!(s.balance(&flow.exchange), 700_000_000);
    assert_eq!(s.balance(&flow.relayer), 15_000_000);
    assert_eq!(s.balance(&vault), s.vault.status().tvl);
}

/// Whether `proof` verifies under the embedded key, with the vault's domain.
fn verifies(s: &Setup, proof: &TxProof) -> bool {
    let env = &s.env;
    let mut inputs = soroban_sdk::Vec::new(env);
    for x in [
        &proof.root,
        &proof.public_amount,
        &proof.ext_data_hash,
        &s.vault.config().domain,
    ] {
        inputs.push_back(Bn254Fr::from_u256(x.clone()));
    }
    for v in [&proof.input_nullifiers, &proof.output_commitments] {
        for x in v.iter() {
            inputs.push_back(Bn254Fr::from_u256(x));
        }
    }
    verifier::verify(env, &VerifyingKey::embedded(env), &proof.proof, inputs)
}

#[test]
fn a_shield_cannot_spend_a_real_note() {
    let flow = Flow::at("transfer");
    let s = &flow.s;
    let env = &s.env;
    let refused = fixtures::refused("shield_spending_a_note");
    assert_eq!(refused["after"], "admit");
    let ext = fixtures::ext(env, &refused);
    let mut proof = fixtures::proof(env, &refused);

    // The proof is valid: it spends Alice's admitted note against the current root.
    assert_eq!(proof.root, s.vault.current_root());
    assert!(verifies(s, &proof));

    // As a shield it is refused, and no proof of that spend can name the empty root.
    let alice = flow.alice.clone();
    assert_eq!(
        outcome(s.vault.try_shield(&proof, &ext, &alice)),
        Err(Error::NonEmptyRoot)
    );
    proof.root = fixtures::field(env, &fixtures::proofs()["empty_root"]);
    assert_eq!(
        outcome(s.vault.try_shield(&proof, &ext, &alice)),
        Err(Error::InvalidProof)
    );
    assert!(!s.vault.is_spent(&proof.input_nullifiers.get_unchecked(0)));

    // The note it tried to spend is still spendable: the transfer that spends it goes through.
    flow.run(&fixtures::step("transfer")).unwrap();
}

#[test]
fn a_real_proof_spending_a_spent_note_in_either_slot_is_refused() {
    for (name, slot) in [("double_spend_slot0", 0), ("double_spend_slot1", 1)] {
        let flow = Flow::at("unshield_self");
        let s = &flow.s;
        let refused = fixtures::refused(name);
        assert_eq!(refused["after"], "unshield_muxed");
        let proof = fixtures::proof(&s.env, &refused);
        assert!(verifies(s, &proof), "{name}");
        let spent = proof.input_nullifiers.get_unchecked(slot);
        let fresh = proof.input_nullifiers.get_unchecked(1 - slot);
        assert!(s.vault.is_spent(&spent) && !s.vault.is_spent(&fresh));
        let balance = s.balance(&flow.bob);

        assert_eq!(flow.run(&refused), Err(Error::NullifierSpent), "{name}");
        assert!(!s.vault.is_spent(&fresh));
        assert_eq!(s.balance(&flow.bob), balance);
    }
}
