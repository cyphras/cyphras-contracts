//! Every event carries one snake_case topic, its name, and map-shaped data.

use soroban_sdk::{contractevent, Address, Bytes, MuxedAddress, U256};

use crate::storage::Limits;

#[contractevent]
pub struct DepositPending {
    pub id: u64,
    pub depositor: Address,
    pub amount: i128,
    pub commitment0: U256,
    pub commitment1: U256,
    pub created_at: u64,
}

#[contractevent]
pub struct DepositFlagged {
    pub id: u64,
    pub reason: u32,
}

/// `reason` is the code of the flag that was cleared.
#[contractevent]
pub struct DepositUnflagged {
    pub id: u64,
    pub reason: u32,
}

#[contractevent]
pub struct Attested {
    pub up_to: u64,
}

#[contractevent]
pub struct DepositAdmitted {
    pub id: u64,
    pub leaf_index0: u64,
    pub leaf_index1: u64,
}

/// `reason` is 0 when the depositor cancelled, otherwise the flag's reason code.
#[contractevent]
pub struct DepositRefunded {
    pub id: u64,
    pub reason: u32,
}

#[contractevent]
pub struct NewCommitment {
    pub index: u64,
    pub commitment: U256,
    pub encrypted_output: Bytes,
}

#[contractevent]
pub struct NewNullifier {
    pub nullifier: U256,
}

/// Repeats what the token transfers of a `transact` show, so a watcher need not join them.
#[contractevent]
pub struct Settled {
    pub ext_amount: i128,
    pub fee: i128,
    pub recipient: MuxedAddress,
    pub relayer: Address,
}

#[contractevent]
pub struct Paused {
    pub deposits: bool,
    pub transfers: bool,
}

#[contractevent]
pub struct Halted {
    pub until: u64,
}

#[contractevent]
pub struct Resumed {
    pub next_halt_at: u64,
}

#[contractevent]
pub struct LimitsQueued {
    pub limits: Limits,
    pub ready_at: u64,
}

/// For a tightening, which applies at once, `ready_at` is the time it was applied.
#[contractevent]
pub struct LimitsApplied {
    pub limits: Limits,
    pub ready_at: u64,
}

#[contractevent]
pub struct LimitsCancelled {
    pub limits: Limits,
    pub ready_at: u64,
}
