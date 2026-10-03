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

/// Repeats what the token transfers of a payment show, so a watcher need not join them.
/// `exit_id` is set when `release` or `claim` completes an exit from the exit queue, and absent
/// when `transact` paid at once. For an exit paid in several steps, `ext_amount` and `fee` are
/// the parts of the last step; the earlier ones appear in `exit_paid`.
#[contractevent]
pub struct Settled {
    pub ext_amount: i128,
    pub fee: i128,
    pub recipient: MuxedAddress,
    pub relayer: Address,
    pub exit_id: Option<u64>,
}

/// An exit that waits in the exit queue; `release` pays it in turn.
#[contractevent]
pub struct ExitQueued {
    pub id: u64,
    pub ext_amount: i128,
    pub fee: i128,
    pub recipient: MuxedAddress,
    pub relayer: Address,
}

/// Part payment of an exit that is not yet paid in full, by `release` from the head of the queue or
/// by `claim` of a stranded exit. `payout_left` and `fee_left` stay owed.
#[contractevent]
pub struct ExitPaid {
    pub id: u64,
    pub payout_paid: i128,
    pub fee_paid: i128,
    pub payout_left: i128,
    pub fee_left: i128,
}

/// A released exit with a part the asset contract refused to transfer. `payout` and `fee` are
/// what it still owes, which stays reserved until `claim` pays it.
#[contractevent]
pub struct ExitStranded {
    pub id: u64,
    pub payout: i128,
    pub fee: i128,
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
