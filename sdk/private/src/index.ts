export { PrivateWallet } from "./wallet/wallet.ts";
export type {
  AddressOptions,
  ConnectionOptions,
  OpenOptions,
  OperationView,
  PlanView,
  QuoteRequest,
  RetryRequest,
  SendRequest,
  StateReset,
  SyncSummary,
  UnshieldRequest,
  ViewOnlyOptions,
} from "./wallet/wallet.ts";
export type { ConfirmSpend, SpendQuote, SpendReview, Submission } from "./wallet/spend.ts";
export type { Warning, WarningCode } from "./wallet/nudges.ts";
export type { Balance, HistoryEntry, HistoryKind } from "./wallet/history.ts";
export type { DepositInfo, ScreeningKind, ShieldReceipt } from "./wallet/deposits.ts";
export type { VaultLimitsView } from "./wallet/limits.ts";
export type { DisclosureCheck, PaymentDisclosure } from "./wallet/disclosure.ts";
export type { ExitPosition } from "./wallet/exits.ts";
export type { Verification, ServiceState } from "./wallet/services.ts";
export type { ExitPart, PlanState, Route } from "./wallet/state.ts";
export type { SyncLimits } from "./wallet/sources.ts";
export type { NetworkFee, NetworkFeeCaps, TransactionSigner } from "./vault/invoke.ts";

export { isKeyDerivationMessage, keySource, SIGNATURE_MESSAGE } from "./keysource.ts";
export type {
  KeySource,
  KeySourceContext,
  MessageSigner,
  RandomKeySource,
  SeedMaterial,
} from "./keysource.ts";

export { MemoryStore } from "./storage.ts";
export type { KeyValueStore } from "./storage.ts";

export { loadCircuit } from "./artifacts.ts";
export type { ArtifactName, ArtifactPins, ArtifactSource } from "./artifacts.ts";
export { circuitInputs } from "./prover.ts";
export type {
  CircuitArtifacts,
  CircuitPins,
  Groth16Proof,
  Prover,
  TransactionWitness,
} from "./prover.ts";

export { PINNED_DEPLOYMENTS } from "./deployments.ts";
export type { Deployment, DeploymentName, RelayerEndpoint } from "./deployments.ts";

export { decodeAddress, decodeViewingKey } from "./address.ts";
export type { EncodingRule, ViewingKey } from "./address.ts";
export type { Network } from "./keys.ts";

export { CyphrasError } from "./errors.ts";
export type { ErrorCode, ErrorDetails } from "./errors.ts";
export type { FetchLike } from "./net/http.ts";
