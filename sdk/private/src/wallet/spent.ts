import { randomBytes } from "../bytes.ts";
import { CyphrasError } from "../errors.ts";
import { type LedgerEntries, type SorobanRpc, keyId } from "../net/rpc.ts";
import { nullifierKey } from "../vault/state.ts";
import { ownKey } from "./archive.ts";
import type { Core } from "./core.ts";
import type { Plan } from "./state.ts";
import { isActive } from "./sync.ts";

// The vault's error for a proof whose nullifier it has an entry for.
const NULLIFIER_SPENT = 123;

// What the vault's entries of a plan's two nullifiers, as every RPC provider read them, say of its
// notes. "spent": the notes whose nullifier every provider shows spent are marked spent; the plan,
// whose other nullifier every provider shows unspent, can neither have landed, as its landing
// writes both, nor land any more, and is superseded; with both shown spent it may have landed
// itself, and the sync settles it. "disputed": the providers differ on a nullifier, or the vault's
// refusal named a nullifier none of them shows spent. "unspent": none shows one spent.
// "unconfirmed": not every configured provider answered. "unread": the wallet knows too few public
// spends to hide the read among, so it made none.
export type SpentCheck = "spent" | "disputed" | "unspent" | "unconfirmed" | "unread";

// Each of a plan's nullifiers is read among at least this many nullifiers of other users' spends.
export const DECOYS_PER_KEY = 31;

const randomBelow = (n: number): number =>
  Math.floor((new DataView(randomBytes(4).buffer).getUint32(0) / 2 ** 32) * n);

function shuffle<T>(xs: readonly T[]): T[] {
  const out = [...xs];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomBelow(i + 1);
    [out[i], out[j]] = [out[j] as T, out[i] as T];
  }
  return out;
}

// The plan's nullifiers among nullifiers of public spends that are none of this wallet's, drawn at
// random from those the syncs kept, in random order; undefined when too few are known.
function batchOf(core: Core, plan: Plan): bigint[] | undefined {
  const { state } = core;
  const own = new Set([
    ...state.notes.flatMap((n) => (n.nf === undefined ? [] : [n.nf])),
    ...state.plans.flatMap((p) => p.nullifiers),
  ]);
  const pool = [...new Set(state.publicNullifiers)].filter((nf) => !own.has(nf));
  const wanted = DECOYS_PER_KEY * plan.nullifiers.length;
  if (pool.length < wanted) return undefined;
  return shuffle([...plan.nullifiers, ...shuffle(pool).slice(0, wanted)]);
}

// Reads the entries of the plan's nullifiers from every RPC provider, in one request each that
// holds the same batch of keys, so no provider sees the plan's keys alone or a batch another did
// not. An entry, live or archived, is the vault's record of a spend, which it never removes; only
// the plan's own keys are looked at. With one provider configured its word alone counts, as it does
// for the sync's spends; with two, both must answer and agree.
async function readSpends(
  core: Core,
  plan: Plan,
): Promise<
  { readonly spent: readonly ("yes" | "no" | "disputed")[]; readonly ledger: number } | "unread"
> {
  const { services, deployment } = core;
  const rpcs: SorobanRpc[] = [services.rpc, ...(services.second ? [services.second.rpc] : [])];
  const batch = batchOf(core, plan);
  if (batch === undefined) return "unread";
  const keys = plan.nullifiers.map((nf) => nullifierKey(deployment.vault, nf));
  const asked = batch.map((nf) => nullifierKey(deployment.vault, nf));
  const replies = await Promise.all(
    rpcs.map((rpc) =>
      rpc.getLedgerEntries(asked).catch((err: unknown): LedgerEntries | undefined => {
        if (err instanceof CyphrasError) return undefined;
        throw err;
      }),
    ),
  );
  const answered = replies.filter((r): r is LedgerEntries => r !== undefined);
  if (answered.length < rpcs.length) return { spent: [], ledger: 0 };
  const shown = (reply: LedgerEntries, i: number): boolean => {
    const key = keys[i] as (typeof keys)[number];
    const entry = reply.entries.get(keyId(key));
    return entry !== undefined && ownKey(entry.data) === keyId(key);
  };
  return {
    spent: keys.map((_key, i) => {
      const seen = answered.map((reply) => shown(reply, i));
      return seen.every(Boolean) ? "yes" : seen.some(Boolean) ? "disputed" : "no";
    }),
    ledger: Math.min(...answered.map((r) => r.latestLedger)),
  };
}

/**
 * Reads whether the notes of a plan that has not landed were spent, after its submission failed in
 * a way a spent note explains, and marks those every provider shows spent. `named`: the vault's
 * refusal named a spent nullifier. Only a plan the wallet still follows is looked at.
 *
 * Privacy: the read tells each RPC provider that the wallet asks about these keys just after a
 * payment failed, which could tie the provider's view of the wallet, as its IP address, to the
 * notes. The plan's two keys are therefore asked only inside one batch with at least 31 times as
 * many keys of other users' spends, taken from the public spends the wallet's syncs read, in random
 * order, and every provider gets the same batch. This hides which keys are the plan's only as far
 * as their entries look alike: the decoys are all spent, so a key of the plan the vault shows
 * unspent stands out, while one it shows spent, as a note spent elsewhere, does not. A wallet that
 * knows too few public spends reads nothing, and the sync settles the plan as before.
 */
export async function checkSpent(core: Core, plan: Plan, named: boolean): Promise<SpentCheck> {
  if (!isActive(plan)) return "unspent";
  const read = await readSpends(core, plan);
  if (read === "unread") return read;
  const { spent, ledger } = read;
  if (spent.length === 0) return "unconfirmed";
  if (spent.includes("disputed") || (named && !spent.includes("yes"))) return "disputed";
  if (!spent.includes("yes")) return "unspent";
  for (const input of plan.inputs) {
    if (spent[plan.nullifiers.indexOf(input.nf)] !== "yes") continue;
    const note = core.state.notes.find((n) => n.pos === input.pos);
    if (note !== undefined && note.spent === undefined) {
      note.spent = { txHash: undefined, ledger, external: true };
    }
  }
  if (spent.includes("no")) plan.state = "superseded";
  return "spent";
}

// Whether a failed submission may come from a spent note: the vault's refusal of a self-relayed
// call names it, or such a call failed on chain, where the RPC reports no contract error; or a
// relayer refused or failed the request with "rejected", which it answers for spent notes too.
function spentSign(err: unknown, relayed: boolean): { named: boolean } | undefined {
  if (!(err instanceof CyphrasError)) return undefined;
  const { details } = err;
  if (relayed) {
    return err.code === "service_rejected" && details["code"] === "rejected"
      ? { named: false }
      : undefined;
  }
  if (err.code !== "transaction_failed") return undefined;
  if (details["contractError"] === NULLIFIER_SPENT) return { named: true };
  const onChain =
    typeof details["hash"] === "string" &&
    details["refused"] !== true &&
    details["archived"] !== true &&
    details["contractError"] === undefined;
  return onChain ? { named: false } : undefined;
}

// The error a failed submission raises once its notes were looked at: the same one, telling what
// the providers showed, or nullifier_disputed when they disagree.
export async function afterFailure(
  core: Core,
  plan: Plan,
  err: unknown,
  relayed: boolean,
): Promise<unknown> {
  const sign = spentSign(err, relayed);
  if (sign === undefined || !(err instanceof CyphrasError)) return err;
  const check = await checkSpent(core, plan, sign.named);
  if (check === "unread") return err;
  if (check === "disputed") {
    const disputed = new CyphrasError(
      "nullifier_disputed",
      "the vault refused the payment as spending a note already spent, and the RPC providers do not agree that it is: nothing changed, and the payment keeps its notes until its fate is known",
      { ...err.details, spentCheck: check },
      { cause: err },
    );
    if (!relayed) plan.error = disputed.code;
    plan.errorMessage = disputed.message;
    await core.save();
    return disputed;
  }
  if (check === "unspent" && !sign.named) return err;
  await core.save();
  return new CyphrasError(
    err.code,
    err.message,
    { ...err.details, spentCheck: check },
    {
      cause: err.cause,
    },
  );
}
