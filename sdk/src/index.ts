export { PrivateWallet } from "./wallet/wallet.ts";
export type {
  ConnectionOptions,
  OpenOptions,
  OperationView,
  PlanView,
  RetryRequest,
  SendRequest,
  SyncSummary,
  UnshieldRequest,
  ViewOnlyOptions,
} from "./wallet/wallet.ts";
export type { ConfirmSpend, SpendReview, Submission } from "./wallet/spend.ts";
export type { Warning, WarningCode } from "./wallet/nudges.ts";
export type { Balance, HistoryEntry, HistoryKind } from "./wallet/history.ts";
export type { DepositInfo, ShieldReceipt } from "./wallet/deposits.ts";
export type { DisclosureCheck, PaymentDisclosure } from "./wallet/disclosure.ts";
export type { ExitPosition } from "./wallet/exits.ts";
export type { Verification, ServiceState } from "./wallet/services.ts";
export type { PlanState } from "./wallet/state.ts";
export type { SyncLimits } from "./wallet/sources.ts";
export type { NetworkFee, NetworkFeeCaps, TransactionSigner } from "./vault/invoke.ts";

export { keySource, SIGNATURE_MESSAGE } from "./keysource.ts";
export type {
  KeySource,
  KeySourceContext,
  MessageSigner,
  RandomKeySource,
  SeedMaterial,
} from "./keysource.ts";

export { MemoryStore } from "./storage.ts";
export type { KeyValueStore } from "./storage.ts";

export type { ArtifactName, ArtifactPins, ArtifactSource } from "./artifacts.ts";
export type { CircuitArtifacts, Groth16Proof, Prover, TransactionWitness } from "./prover.ts";

export { PINNED_DEPLOYMENTS } from "./deployments.ts";
export type { Deployment, DeploymentName, RelayerEndpoint } from "./deployments.ts";

export { decodeAddress, decodeViewingKey } from "./address.ts";
export type { EncodingRule, ViewingKey } from "./address.ts";
export type { Network } from "./keys.ts";

export { CyphrasError } from "./errors.ts";
export type { ErrorCode, ErrorDetails } from "./errors.ts";
export type { FetchLike } from "./net/http.ts";
