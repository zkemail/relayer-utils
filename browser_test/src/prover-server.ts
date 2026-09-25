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


async function main() {
  await init();
  console.log("WASM initialized");

  const sdk = zkeSdk({
    baseUrl: "https://staging-conductor.zk.email",
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

    const wasmRes = await fetch(wasmUrl);
    const wasmBuff = new Uint8Array(await wasmRes.arrayBuffer());
    console.log("Starting proof generation...");
    const zkeyPath = path.join(__dirname, "../circuit.zkey");
    if (!fs.existsSync(zkeyPath)) {
      console.log(
        `File ${zkeyPath} not found. Please download this file to your local environment before running the prover.`
      );
      throw new Error(`Missing required file: ${zkeyPath}`);
    }
    const { proof, publicSignals } = await groth16.fullProve(
      circuitInputsObject,
      wasmBuff,
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