import zkeSdk from "@zk-email/sdk";
import {
  init,
  generateCircuitInputsWithDecomposedRegexesAndExternalInputs,
} from "../../pkg/relayer_utils";
import fs from "node:fs";
import path from "node:path";

import { groth16 } from "snarkjs";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const blueprintId = "8241f8bd-9fe7-443d-a09d-0150dcc7e85e";

import pako from "pako";

/**
 * Unzips (decompresses) an array of zipped ArrayBuffers and merges them into a single Uint8Array.
 * This is useful for preparing circuit input data that may be compressed.
 * 
 * @param buffers Array of zipped ArrayBuffers
 * @returns Uint8Array of the merged, unzipped data
 */
function mergeAndUnzipArrayBuffers(buffers: ArrayBuffer[]): Uint8Array {
  // Unzip each buffer using pako
  const unzippedArrays = buffers.map((buffer) => {
    const uint8Array = new Uint8Array(buffer); // Convert ArrayBuffer to Uint8Array

    return pako.ungzip(uint8Array);
  });

  let mergedUnzipped;
    const totalLength = unzippedArrays.reduce((sum, arr) => sum + arr.length, 0);
    mergedUnzipped = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of unzippedArrays) {
      mergedUnzipped.set(arr, offset);
      offset += arr.length;
    }
  return mergedUnzipped;
}

async function main() {
  await init();
  console.log("WASM initialized");

  const sdk = zkeSdk({
    baseUrl: "https://dev-conductor.zk.email",
    logging: { enabled: true, level: "debug" },
  });

  try {
    console.log("getting blueprint");
    let blueprint;
    try {
      blueprint = await sdk.getBlueprintById(blueprintId);
    } catch (error) {
      console.error("Failed to fetch blueprint:", error);
      throw error;
    }

    console.log("blueprint: ", blueprint);

    const eml = fs.readFileSync(
      path.join(__dirname, "../public/residency.eml"),
      "utf-8"
    );

    try {
      const isValidEml = await blueprint.validateEmail(eml!);
      console.log("isValidEml: ", isValidEml);
    } catch (err) {
      console.error("Email is not valid: ", err);
    }

    const externalInputs: any[] = [];

    const params = {
      maxHeaderLength: blueprint.props.emailHeaderMaxLength || 256,
      maxBodyLength: blueprint.props.emailBodyMaxLength || 2560,
      ignoreBodyHashCheck: blueprint.props.ignoreBodyHashCheck || false,
      removeSoftLineBreaks: blueprint.props.removeSoftLinebreaks || true,
      shaPrecomputeSelector: blueprint.props.shaPrecomputeSelector,
    };

    const regexGraphs = await blueprint.getCircomRegexGraphs();

    const decomposedRegexesCleaned = blueprint.props.decomposedRegexes
      .map((dcr) => {
        const regexGraph = regexGraphs[`${dcr.name}_regex.json`];
        if (!regexGraph) {
          throw new Error(
            `No regexGraph was compiled for decomposedRegexe ${dcr.name}`
          );
        }

        let haystackLocation;
        if (dcr.location === "header") {
          haystackLocation = "header";
        } else {
          haystackLocation = "body";
        }

        const maxHaystackLength =
          dcr.location === "header"
            ? blueprint.props.emailHeaderMaxLength
            : blueprint.props.emailBodyMaxLength;

        if (!maxHaystackLength) return;

        return {
          name: dcr.name,
          haystackLocation,
          maxHaystackLength: maxHaystackLength,
          maxMatchLength: 128,
          regexGraphJson: JSON.stringify(regexGraph),
          parts: dcr.parts.map((p: any) => ({
            is_public: p.isPublic || !!p.is_public,
            regex_def: p.regexDef || !!p.regex_def,
            ...(p.isPublic && { maxLength: 32 }),
          })),
          provingFramework: "circom",
        };
      })
      .filter(Boolean);

    const inputs =
      await generateCircuitInputsWithDecomposedRegexesAndExternalInputs(
        eml!,
        decomposedRegexesCleaned as any,
        externalInputs,
        params
      );

    const circuitInputsObject: any = {};
    for (const [key, value] of inputs) {
      if (value && typeof value === "object" && value instanceof Map) {
        circuitInputsObject[key] = Object.fromEntries(value);
      } else if (value) {
        circuitInputsObject[key] = value;
      }
    }

    console.log("circuitInputsObject: ", circuitInputsObject);

    const [chunkedZkeyUrls, wasmUrl] = await Promise.all([
      blueprint.getChunkedZkeyDownloadLinks(),
      blueprint.getWasmFileDownloadLink(),
    ]);

    // console.log("Downloading WASM and zkey files... \n", wasmUrl, "\nchunkedZkeyUrls \n",chunkedZkeyUrls);
    const wasmRes = await fetch(wasmUrl);
    const wasmBuff = await wasmRes.arrayBuffer();
    // const zkeyPromises = chunkedZkeyUrls.map(({ url }) =>
    //   fetch(url).then((res) => res.arrayBuffer())
    // );
    // console.log("\n zkeyPromises \n", zkeyPromises);
    // const zkeyChunks = await Promise.all(zkeyPromises);
    // console.log("Downloads complete.", zkeyChunks);
    // const zkeyBuff = mergeAndUnzipArrayBuffers(zkeyChunks);
    // Read the circuit zkey file locally instead of downloading from chunked URLs
    let circuit = await fs.promises.readFile(path.join(__dirname, '../circuit.zkey'));
    let wasm = await fs.promises.readFile(path.join(__dirname, '../circuit.wasm'));
    console.log("Starting proof generation...");
    const wasmPath = path.join(__dirname, "../circuit.wasm");
    const zkeyPath = path.join(__dirname, "../circuit.zkey");

    const { proof, publicSignals } = await groth16.fullProve(
      circuitInputsObject,
      wasmPath,
      zkeyPath
    );
    console.log("Proof generation finished.");

    console.log("Proof: \n", proof);
    console.log("Public Signals: \n", publicSignals);
  } catch (err) {
    console.error("Failed to prove: ", err);
  }
}

main().then((x)=> console.log("Proof generation finally happenend 🎉")).catch(console.error);

