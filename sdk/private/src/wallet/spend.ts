import { Address, MuxedAccount } from "@stellar/stellar-base";
import { decodeAddress, encodeAddress } from "../address.ts";
import { hexToBytes, randomBytes } from "../bytes.ts";
import { CyphrasError, fail } from "../errors.ts";
import {
  type ExtData,
  extDataFromJson,
  extDataToJson,
  extDataToScVal,
  isAccountId,
  isContractId,
  isMuxedAccountId,
  txProofFromJson,
  txProofToJson,
  txProofToScVal,
} from "../extdata.ts";
import { addressKeyFor, type AddressKey } from "../keys.ts";
import type { HeldRequest, Quote, RelayerClient } from "../net/relayer.ts";
import { proveTransaction } from "../proving.ts";
import { buildTransaction, type BuiltTransaction, type ExtTerms } from "../transaction.ts";
import { type TransactionSigner, invokeVault } from "../vault/invoke.ts";
import type { VaultInstance } from "../vault/state.ts";
import {
  type Core,
  chainReads,
  invokeContext,
  newId,
  selectNotes,
  spendNote,
  spendableNotes,
  spendingKeys,
} from "./core.ts";
import { type Warning, unshieldWarnings } from "./nudges.ts";
import type { OwnedNote, Plan, PlanState, RootCheck, Route } from "./state.ts";

/** What the user is asked to confirm before a spend is proved. */
export interface SpendReview {
  readonly kind: "send" | "unshield";
  readonly amount: bigint;
  readonly fee: bigint;
  readonly to: string;
  // The relayer's URL, or undefined for a self-relayed unshield.
  readonly relayer: string | undefined;
  readonly warnings: readonly Warning[];
  // More than 1 for an unshield split across transactions.
  readonly parts: number;
}

/**
 * Returns true to go ahead. Without a confirm callback, a spend proceeds only when it raises no
 * warning, and the fee it pays is capped by maxFee alone.
 */
export type ConfirmSpend = (review: SpendReview) => boolean | Promise<boolean>;

/** The result of a spend: its plan in the submission state machine. */
export interface Submission {
  readonly planId: string;
  readonly state: PlanState;
  readonly txHash: string | undefined;
  readonly fee: bigint;
}

// Clients set the deadline about ten minutes of ledgers ahead and prove again after it passes.
export const DEADLINE_LEDGERS = 120;
const MAX_NOT_BEFORE_SECONDS = 24 * 3600;
const FEE_RETRIES = 2;
// The relayer runs a delayed request at a random moment in the 10 minutes after not_before, and
// takes one only while its deadline lies this many ledgers past the end of that window, which it
// predicts from the pace of recent ledgers.
const JITTER_SECONDS = 600;
const RELAYER_DEADLINE_MARGIN = 20;

const randomBelow = (n: number): number =>
  Math.floor((new DataView(randomBytes(4).buffer).getUint32(0) / 2 ** 32) * n);

export interface SpendIntent {
  readonly kind: "send" | "unshield";
  readonly to: string;
  readonly amount: bigint;
  readonly maxFee: bigint;
  readonly relayers: readonly RelayerClient[];
  readonly selfRelay: TransactionSigner | undefined;
  readonly confirm: ConfirmSpend | undefined;
  readonly notBefore: number | undefined;
  // A retry spends the stalled plan's notes, so at most one of the two can land.
  readonly inputs: readonly OwnedNote[] | undefined;
  readonly retryOf: string | undefined;
  readonly operationId: string | undefined;
  readonly parts: number;
  // The caller agreed that a payout to the asset's issuer is burned.
  readonly burnToIssuer: boolean;
  // Called with each plan as it is saved, before anything of it leaves the device.
  readonly onPlan: ((plan: Plan) => void) | undefined;
}

interface Relay {
  readonly client: RelayerClient;
  readonly quote: Quote;
  // The fee address the relayer's health reported and, for a pinned relayer, the pinned one.
  readonly feeAddress: string;
}

function checkQuote(core: Core, quote: Quote, feeAddress: string, cap: bigint): void {
  const { deployment } = core;
  const bad = (what: string): never => fail("quote_invalid", `the quote ${what}`);
  if (quote.vault !== deployment.vault || quote.networkId !== core.services.networkId) {
    bad("is for another vault");
  }
  if (quote.feeAddress !== feeAddress) bad("names another fee address");
  if (quote.asset !== deployment.asset.name) bad("is in another asset");
  // A fee off the pinned tier could fingerprint the moment of the quote.
  if (quote.tier !== deployment.feeTier || quote.fee % deployment.feeTier !== 0n)
    bad("is off the fee tier");
  if (quote.marginBps < 0 || quote.marginBps > 1_000) bad("takes a margin above 10 percent");
  if (quote.fee < 0n) bad("is negative");
  if (quote.validUntil * 1000 < core.now()) bad("has expired");
  if (quote.fee > cap) {
    fail("fee_above_cap", "the relayer's fee is above the cap", {
      fee: quote.fee.toString(),
      cap: cap.toString(),
    });
  }
}

// The first relayer that reports the pinned vault and network and quotes within the cap.
async function chooseRelay(
  core: Core,
  candidates: readonly RelayerClient[],
  cap: bigint,
): Promise<Relay> {
  let last: unknown;
  for (const client of candidates) {
    try {
      const health = await client.health();
      const pinned = core.deployment.relayers.find((r) => r.url === client.url);
      if (health.vault !== core.deployment.vault || health.networkId !== core.services.networkId) {
        fail("deployment_mismatch", "the relayer serves another vault");
      }
      if (pinned !== undefined && health.feeAddress !== pinned.feeAddress) {
        fail("deployment_mismatch", "the relayer names another fee address");
      }
      if (health.paused) {
        fail(
          "service_unavailable",
          "the relayer has paused relaying; another relayer, or self-relay for an unshield, can take the payment",
          { service: "relayer", paused: true },
        );
      }
      if (!health.ready)
        fail("service_unavailable", "the relayer is not ready", { service: "relayer" });
      const quote = await client.quote();
      checkQuote(core, quote, health.feeAddress, cap);
      return { client, quote, feeAddress: health.feeAddress };
    } catch (err) {
      if (!(err instanceof CyphrasError)) throw err;
      if (err.code === "deployment_mismatch") throw err;
      last = err;
    }
  }
  if (last instanceof CyphrasError) throw last;
  return fail("service_unavailable", "no relayer is available", { service: "relayer" });
}

// A payout to an account that does not exist yet creates it. The vault accepts one only in the
// native asset, and of at least the new account's minimum balance of two base reserves.
const NEW_ACCOUNT_MIN_PAYOUT = 10_000_000n;

interface Destination {
  readonly createdLedger: number | undefined;
  readonly latestLedger: number;
  readonly createsAccount: boolean;
}

// The issuer of an issued asset, which burns what it receives of its own asset.
function issuerOf(assetName: string, to: string): boolean {
  const issuer = assetName.split(":")[1];
  const account = isMuxedAccountId(to)
    ? MuxedAccount.fromAddress(to, "0").baseAccount().accountId()
    : to;
  return issuer !== undefined && account === issuer;
}

// A payout to the asset's own issuer is burned, as a classic payment to it would be; the vault
// takes it, so the caller must agree to it.
export function checkIssuer(assetName: string, to: string, burn: boolean): void {
  if (issuerOf(assetName, to) && !burn) {
    fail("destination_is_issuer", "the destination is the asset's issuer, which burns the payout", {
      payout: "burned",
    });
  }
}

// The destination must be able to receive before anything is proved.
async function checkDestination(
  core: Core,
  to: string,
  amount: bigint,
  burnToIssuer: boolean,
): Promise<Destination> {
  const { deployment } = core;
  if (!isAccountId(to) && !isContractId(to) && !isMuxedAccountId(to)) {
    fail(
      "destination_invalid",
      "the destination is not a Stellar account, muxed account or contract",
    );
  }
  if (to === deployment.vault) fail("destination_invalid", "the vault cannot be the destination");
  checkIssuer(deployment.asset.name, to, burnToIssuer);
  const dest = await core.services.vault.destination(to, deployment.asset.name);
  if (!dest.exists) {
    if (deployment.asset.name !== "native" || isContractId(to)) {
      fail("destination_invalid", "the destination does not exist on the network");
    }
    if (amount < NEW_ACCOUNT_MIN_PAYOUT) {
      fail(
        "destination_invalid",
        "the destination does not exist yet, and a payout that creates it must be at least 1 XLM",
        { minimum: NEW_ACCOUNT_MIN_PAYOUT.toString() },
      );
    }
    return { createdLedger: undefined, latestLedger: dest.latestLedger, createsAccount: true };
  }
  // The issuer holds no trustline for its own asset.
  if (
    deployment.asset.name !== "native" &&
    !isContractId(to) &&
    !issuerOf(deployment.asset.name, to)
  ) {
    if (dest.trustline === undefined || !dest.trustline.authorized) {
      fail("destination_invalid", "the destination has no authorized trustline for the asset");
    }
    if (dest.trustline.room < amount) {
      fail("destination_invalid", "the destination's trustline limit is too low for the amount");
    }
  }
  return {
    createdLedger: dest.createdLedger,
    latestLedger: dest.latestLedger,
    createsAccount: false,
  };
}

function vaultOpen(
  instance: VaultInstance,
  kind: "send" | "unshield" | "shield",
  now: number,
): void {
  if (BigInt(Math.floor(now / 1000)) < instance.status.haltedUntil) {
    fail("vault_unavailable", "the vault is halted", {
      until: instance.status.haltedUntil.toString(),
    });
  }
  if (kind === "send" && instance.status.transfersPaused) {
    fail("vault_unavailable", "transfers are paused");
  }
  if (kind === "shield" && instance.status.depositsPaused) {
    fail("vault_unavailable", "deposits are paused");
  }
}

// Outflow rules for a transact: the single-exit cap and admitted value only. Returns whether the
// payout will wait in the exit queue.
function checkOutflow(instance: VaultInstance, outflow: bigint, now: number): boolean {
  const { limits, status } = instance;
  if (outflow > limits.maxDailyOutflow) {
    fail("limit_exceeded", "the payout and fee exceed the vault's cap for one exit", {
      maxPerTransaction: limits.maxDailyOutflow.toString(),
    });
  }
  // Pending deposits stay claimable by their depositors and queued exits are owed already.
  if (outflow > status.tvl - status.pendingTotal - status.queuedTotal) {
    fail("vault_unavailable", "the vault holds too little admitted value for this payout");
  }
  const day = BigInt(Math.floor(now / 86_400_000));
  const usedToday = status.outflowDay === day ? status.outflow : 0n;
  // An exit that pays nothing never waits; any other waits behind those already queued.
  return (
    outflow > 0n &&
    (usedToday + outflow > limits.maxDailyOutflow || status.exitTail > status.exitHead)
  );
}

function planOf(
  core: Core,
  intent: SpendIntent,
  route: Route,
  fee: bigint,
  inputs: readonly OwnedNote[],
  built: BuiltTransaction,
  proof: ReturnType<typeof txProofToJson>,
  createsAccount: boolean,
): Plan {
  return {
    id: newId(),
    kind: intent.kind,
    state: "prepared",
    createdAt: core.now(),
    route,
    amount: intent.amount,
    fee,
    to: intent.to,
    createsAccount,
    inputs: inputs.map((n) => ({ pos: n.pos, nf: n.nf as bigint, value: n.value })),
    nullifiers: built.nullifiers,
    commitments: built.commitments,
    outputs: built.outputs.map((o) => {
      const address = encodeAddress(core.deployment.network, o.address.d, o.address.pkd);
      return {
        cm: o.cm,
        value: o.value,
        address,
        own: address === encodeAddress(core.deployment.network, core.self.d, core.self.pkd),
        rcm: o.rcm,
        esk: o.esk,
      };
    }),
    root: built.witness.root,
    builtAt: (core.state.rootCheck as RootCheck).ledger,
    deadline: built.ext.deadline,
    ext: extDataToJson(built.ext),
    proof,
    notBefore: intent.notBefore,
    operationId: intent.operationId,
    retryOf: intent.retryOf,
    txHash: undefined,
    heldId: undefined,
    ledger: undefined,
    evidence: [],
    relayerStatus: undefined,
    exit: undefined,
    error: undefined,
  };
}

const view = (plan: Plan): Submission => ({
  planId: plan.id,
  state: plan.state,
  txHash: plan.txHash,
  fee: plan.fee,
});

// An error raised once a plan was saved names it: the plan keeps its notes until its fate is
// known, whatever became of its submission.
function naming(err: unknown, plan: Plan | undefined): unknown {
  if (plan === undefined || !(err instanceof CyphrasError) || "planId" in err.details) return err;
  return new CyphrasError(err.code, err.message, { ...err.details, planId: plan.id });
}

// One spend from the review to the submission, with a write-ahead plan saved before anything
// leaves the device and the confirmed fee inside the proof.
export async function spend(core: Core, intent: SpendIntent): Promise<Submission> {
  const keys = spendingKeys(core);
  if (core.prover === undefined || core.artifacts === undefined) {
    fail("invalid_argument", "this wallet was opened without a prover and artifacts");
  }
  if (intent.amount <= 0n) fail("invalid_argument", "the amount must be positive");
  if (intent.kind === "send" && intent.selfRelay !== undefined) {
    fail(
      "invalid_argument",
      "transfers cannot be self-relayed; that would put your account on them",
    );
  }
  if (intent.notBefore !== undefined) {
    const ahead = intent.notBefore - Math.floor(core.now() / 1000);
    if (ahead < 0 || ahead > MAX_NOT_BEFORE_SECONDS) {
      fail("invalid_argument", "notBefore must be within the next 24 hours");
    }
    if (intent.selfRelay !== undefined) fail("invalid_argument", "notBefore needs a relayer");
  }
  const check = core.state.rootCheck;
  if (check?.state !== "verified") {
    fail("tree_unverified", "the local tree is not verified against the vault; sync first");
  }

  const reads = chainReads(core);
  const instance = reads.view.instance;
  vaultOpen(instance, intent.kind, core.now());
  const cap = intent.maxFee < instance.limits.maxFee ? intent.maxFee : instance.limits.maxFee;

  let recipient: AddressKey | undefined;
  let destination: Destination | undefined;
  if (intent.kind === "send") {
    recipient = decodeAddress(core.deployment.network, intent.to);
  } else {
    destination = await checkDestination(core, intent.to, intent.amount, intent.burnToIssuer);
  }

  let attempt = 0;
  let relay =
    intent.selfRelay === undefined ? await chooseRelay(core, intent.relayers, cap) : undefined;
  let retryOf = intent.retryOf;
  let saved: Plan | undefined;
  try {
    for (;;) {
      const fee = relay?.quote.fee ?? 0n;
      const route: Route =
        relay === undefined
          ? { kind: "self", account: (intent.selfRelay as TransactionSigner).publicKey }
          : { kind: "relayer", url: relay.client.url };
      const relayerAddress =
        relay === undefined ? (intent.selfRelay as TransactionSigner).publicKey : relay.feeAddress;
      const outflow = intent.kind === "send" ? fee : intent.amount + fee;
      const willQueue = checkOutflow(instance, outflow, core.now());

      const inputs = intent.inputs ?? selectNotes(spendableNotes(core.state), intent.amount + fee);
      const total = inputs.reduce((s, n) => s + n.value, 0n);
      if (total < intent.amount + fee) {
        fail("insufficient_funds", "the notes of the stalled payment no longer cover the new fee");
      }

      let warnings: Warning[] = [];
      if (intent.kind === "unshield") {
        const spendable = spendableNotes(core.state).reduce((s, n) => s + n.value, 0n);
        const stats = reads.stats;
        warnings = unshieldWarnings({
          to: intent.to,
          amount: intent.amount,
          fee,
          spendable,
          deposits: core.state.deposits,
          notes: core.state.notes,
          now: core.now(),
          destinationCreatedLedger: destination?.createdLedger,
          createsAccount: destination?.createsAccount ?? false,
          latestLedger: destination?.latestLedger ?? 0,
          admittedDeposits: stats?.admittedDeposits,
          selfRelay: relay === undefined,
          willQueue,
        });
      }
      const review: SpendReview = {
        kind: intent.kind,
        amount: intent.amount,
        fee,
        to: intent.to,
        relayer: relay?.client.url,
        warnings,
        parts: intent.parts,
      };
      const confirmed =
        intent.confirm === undefined ? warnings.length === 0 : await intent.confirm(review);
      if (!confirmed) {
        fail("not_confirmed", "the spend was not confirmed", {
          warnings: warnings.map((w) => w.code).join(","),
        });
      }

      const latest = reads.view.ledger;
      // A held request must still be valid at the end of the relayer's window after not_before.
      const delay =
        intent.notBefore === undefined
          ? 0
          : Math.ceil(
              (intent.notBefore + JITTER_SECONDS - Math.floor(core.now() / 1000)) / reads.pace,
            );
      const terms: ExtTerms = {
        vault: core.deployment.vault,
        networkId: hexToBytes(core.services.networkId),
        deadline: latest + delay + DEADLINE_LEDGERS,
        extAmount: intent.kind === "send" ? 0n : -intent.amount,
        fee,
        // A transfer names no party to the payment, only the relayer.
        recipient: intent.kind === "send" ? relayerAddress : intent.to,
        relayer: relayerAddress,
      };
      const change = total - intent.amount - fee;
      const outputs =
        intent.kind === "send"
          ? ([
              { address: recipient as AddressKey, value: intent.amount },
              { address: core.self, value: change },
            ] as const)
          : ([
              { address: core.self, value: change },
              { address: core.self, value: 0n },
            ] as const);
      const spends = inputs.map((note) => {
        const address = addressKeyFor(core.scan.incoming, note.d);
        if (address === undefined) fail("invalid_argument", "a note has an invalid diversifier");
        return spendNote(core.state, note, address);
      });
      const built = buildTransaction({
        keys,
        self: core.self,
        root: check.root,
        domain: core.deployment.domain,
        inputs: spends,
        outputs,
        ext: terms,
      });
      const proof = await proveTransaction(built.witness, core.prover, core.artifacts);
      const plan = planOf(
        core,
        { ...intent, retryOf },
        route,
        fee,
        inputs,
        built,
        txProofToJson(proof),
        destination?.createsAccount ?? false,
      );
      core.state.plans.push(plan);
      intent.onPlan?.(plan);
      await core.save();
      saved = plan;

      if (relay === undefined) {
        return await selfRelay(core, plan, intent.selfRelay as TransactionSigner);
      }
      const result = await relay.client.submit(plan.proof, plan.ext, intent.notBefore);
      if (result.accepted) {
        plan.state = "submitted";
        plan.txHash = result.hash;
        plan.heldId = result.heldId;
        await core.save();
        return view(plan);
      }
      plan.error = result.error;
      await core.save();
      // The relayer saw the proof and could still submit it, so the plan keeps its notes until
      // its deadline; a new proof spends the same notes.
      if (result.error === "fee_too_low" && attempt < FEE_RETRIES) {
        attempt++;
        relay = { ...relay, quote: await relay.client.quote() };
        checkQuote(core, relay.quote, relay.feeAddress, cap);
        intent = { ...intent, inputs };
        retryOf = plan.id;
        continue;
      }
      throw new CyphrasError("service_rejected", "the relayer refused the submission", {
        code: result.error,
        ...(result.reason === undefined ? {} : { reason: result.reason }),
      });
    }
  } catch (err) {
    throw naming(err, saved);
  }
}

// What the relayer reports of a held request. One that was sent, failed or was cancelled is not
// followed by its ID any more.
function takeHeld(plan: Plan, held: HeldRequest): void {
  plan.relayerStatus = held.status;
  if (held.hash !== undefined) plan.txHash = held.hash;
  if (held.status === "failed") plan.error = held.code ?? "unknown";
  if (held.hash !== undefined || held.status === "failed" || held.status === "cancelled") {
    plan.heldId = undefined;
  }
}

// Asks the relayer not to send a request it holds until its not_before. Whatever it answers, the
// wallet sends the request again no more: a relayer that cannot cancel it has sent it, refused it,
// or lost it. True once the request is known not to be sent.
export async function cancelHeld(
  plan: Plan,
  heldId: string,
  client: RelayerClient,
): Promise<boolean> {
  if (await client.cancelHeld(heldId)) {
    plan.relayerStatus = "cancelled";
    plan.heldId = undefined;
    return true;
  }
  const held = await client.held(heldId);
  if (held === undefined) {
    plan.relayerStatus = "unknown";
    plan.heldId = undefined;
    return false;
  }
  takeHeld(plan, held);
  return held.status === "cancelled" || (held.status === "failed" && held.hash === undefined);
}

// A request the relayer holds until its not_before lives in the relayer's memory only. Once sent,
// it has a hash, which the plan takes; the chain's evidence still decides whether it landed. A
// relayer that restarted no longer knows the request, so the same proof goes to it again while
// its deadline, past `latest` at `pace` seconds per ledger, allows; one that failed before it was
// sent, or was cancelled, is followed no further.
export async function followHeld(
  core: Core,
  plan: Plan,
  heldId: string,
  client: RelayerClient,
  latest: number,
  pace: number,
): Promise<void> {
  const held = await client.held(heldId);
  if (held !== undefined) {
    takeHeld(plan, held);
    return;
  }
  if (latest >= plan.deadline) return;
  const now = Math.floor(core.now() / 1000);
  let notBefore = plan.notBefore;
  if (notBefore !== undefined && notBefore <= now) {
    // A new moment, at random within the relayer's window, keeps the inclusion time from following
    // this request as it kept it from following the first; the deadline must still cover it.
    const room = (plan.deadline - latest - RELAYER_DEADLINE_MARGIN) * pace - JITTER_SECONDS;
    if (room <= 0) return;
    notBefore = now + 1 + randomBelow(Math.min(room, JITTER_SECONDS));
  }
  const result = await client.submit(plan.proof, plan.ext, notBefore);
  if (result.accepted) {
    plan.txHash = result.hash;
    plan.heldId = result.heldId;
    plan.relayerStatus = result.hash === undefined ? "held" : "pending";
  } else if (result.error === "duplicate") {
    // The relayer still holds the request after all.
    plan.relayerStatus = "held";
  } else if (result.error === "unavailable" || result.error === "rate_limited") {
    // A busy relayer is asked again in the next sync.
    plan.relayerStatus = "unknown";
  } else {
    plan.relayerStatus = "failed";
    plan.error = result.error;
    plan.heldId = undefined;
  }
}

// The user's own account submits the unshield and pays the network fee. The plan stays
// submitted until a sync shows its nullifiers and commitments in one transaction, as for a relayed
// one; the RPC's word that the transaction succeeded does not confirm it.
async function selfRelay(core: Core, plan: Plan, signer: TransactionSigner): Promise<Submission> {
  const ext: ExtData = extDataFromJson(plan.ext);
  try {
    await invokeVault(
      invokeContext(core),
      signer,
      {
        fn: "transact",
        args: [
          txProofToScVal(txProofFromJson(plan.proof)),
          extDataToScVal(ext),
          new Address(signer.publicKey).toScVal(),
        ],
        transfers: [],
      },
      async (hash) => {
        plan.state = "submitted";
        plan.txHash = hash;
        await core.save();
      },
    );
  } catch (err) {
    if (err instanceof CyphrasError) {
      plan.error = err.code;
      await core.save();
    }
    throw err;
  }
  return view(plan);
}

export const submissionOf = view;
