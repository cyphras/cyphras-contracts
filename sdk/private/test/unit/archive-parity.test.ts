import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { PINNED_DEPLOYMENTS } from "../../src/deployments.ts";
import { CyphrasError } from "../../src/errors.ts";
import {
  type ArchivePin,
  type ArchiveWindow,
  checkWindow,
  parseManifest,
  windowFile,
} from "../../src/net/archive.ts";

const FIXTURES = new URL("../fixtures/archive/", import.meta.url);
const read = (path: string): Uint8Array => new Uint8Array(readFileSync(new URL(path, FIXTURES)));
const json = <T>(path: string): T => JSON.parse(new TextDecoder().decode(read(path))) as T;

// Files the archive tool's own reader was given, each with what that reader said of it: an empty
// goError is a file it takes. The reader here must take exactly the same ones.
interface WindowVector {
  readonly name: string;
  readonly file: string;
  readonly window: Omit<ArchiveWindow, "sha256"> & { readonly sha256?: string };
  readonly goError: string;
}

interface ManifestVector {
  readonly name: string;
  readonly file: string;
  readonly goError: string;
}

const goPin = json<ArchivePin>("go-vectors/pin.json");

// Event data the tool's decoder refuses field by field and the reader here does not check yet.
const DATA_CHECKS = new Set([
  "commitment-extra-field",
  "commitment-not-a-field-element",
  "ciphertext-180-bytes",
  "nullifier-not-a-field-element",
  "deposit-of-zero",
]);

async function verdict(run: () => unknown): Promise<string> {
  try {
    await run();
    return "";
  } catch (err) {
    if (err instanceof CyphrasError && err.code === "archive_fault") return err.message;
    throw err;
  }
}

describe("archive format: the same verdict as the archive tool's reader", () => {
  for (const v of json<WindowVector[]>("go-vectors/windows.json")) {
    const todo = DATA_CHECKS.has(v.name) ? "the event decoder does not check this" : undefined;
    it(`window file: ${v.name}`, { todo }, async () => {
      const w: ArchiveWindow = { ...v.window, sha256: v.window.sha256 };
      const got = await verdict(() => checkWindow(w, read(`go-vectors/${v.file}`), goPin));
      assert.equal(got === "", v.goError === "", `here: "${got}", the tool: "${v.goError}"`);
    });
  }

  for (const v of json<ManifestVector[]>("go-vectors/manifests.json")) {
    it(`manifest: ${v.name}`, async () => {
      const got = await verdict(() => parseManifest(read(`go-vectors/${v.file}`), goPin));
      assert.equal(got === "", v.goError === "", `here: "${got}", the tool: "${v.goError}"`);
    });
  }
});

describe("archive format: the published mainnet archive", () => {
  const mainnet = PINNED_DEPLOYMENTS["mainnet/xlm"];
  assert.ok(mainnet !== null);
  const pin: ArchivePin = {
    vault: mainnet.vault,
    networkPassphrase: mainnet.networkPassphrase,
    deployLedger: mainnet.deployLedger,
  };

  it("reads the manifest and every window as the archive tool wrote them", async () => {
    const manifest = parseManifest(read("mainnet/manifest.json"), pin);
    assert.equal(manifest.windows[0]?.start, 64_938_240);
    assert.equal(manifest.coveredTo, 65_283_839);
    let leaves = 0;
    let nullifiers = 0;
    for (const w of manifest.windows.filter((x) => x.events > 0)) {
      const content = await checkWindow(w, read(`mainnet/${windowFile(w)}`), pin);
      assert.equal(content.leaves[0]?.index, leaves);
      leaves += content.leaves.length;
      nullifiers += content.nullifiers.length;
      assert.ok(content.leaves.every((l) => l.ledger >= pin.deployLedger));
    }
    assert.equal(leaves, 28);
    assert.equal(nullifiers, 28);
  });

  it("refuses the mainnet archive for the testnet vault", () => {
    const testnet = PINNED_DEPLOYMENTS["testnet/xlm"];
    assert.ok(testnet !== null);
    assert.throws(
      () =>
        parseManifest(read("mainnet/manifest.json"), {
          vault: testnet.vault,
          networkPassphrase: testnet.networkPassphrase,
          deployLedger: testnet.deployLedger,
        }),
      (err: unknown) => err instanceof CyphrasError && err.code === "archive_fault",
    );
  });
});
