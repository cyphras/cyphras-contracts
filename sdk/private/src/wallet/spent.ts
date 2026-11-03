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
// "unconfirmed": not every configured provider answered.
export type SpentCheck = "spent" | "disputed" | "unspent" | "unconfirmed";

// Reads the entries of the plan's nullifiers from every RPC provider. An entry, live or archived,
// is the vault's record of a spend, which it never removes. With one provider configured its word
// alone counts, as it does for the sync's spends; with two, both must answer and agree.
async function readSpends(
  core: Core,
  plan: Plan,
): Promise<{ readonly spent: readonly ("yes" | "no" | "disputed")[]; readonly ledger: number }> {
  const { services, deployment } = core;
  const rpcs: SorobanRpc[] = [services.rpc, ...(services.second ? [services.second.rpc] : [])];
  const keys = plan.nullifiers.map((nf) => nullifierKey(deployment.vault, nf));
  const replies = await Promise.all(
    rpcs.map((rpc) =>
      rpc.getLedgerEntries(keys).catch((err: unknown): LedgerEntries | undefined => {
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

// Reads whether the notes of a plan that has not landed were spent, after its submission failed in
// a way a spent note explains, and marks those every provider shows spent. `named`: the vault's
// refusal named a spent nullifier. Only a plan the wallet still follows is looked at.
export async function checkSpent(core: Core, plan: Plan, named: boolean): Promise<SpentCheck> {
  if (!isActive(plan)) return "unspent";
  const { spent, ledger } = await readSpends(core, plan);
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
