// CLIENT SIDE PROOVING DOESN'T WORK FOR NOIR CURRENTLY

import zkeSdk, { Blueprint, DecomposedRegex, ExternalInput, ExternalInputInput, ExternalInputProof, GenerateProofInputsParams, GenerateProofInputsParamsInternal, ProofProps, ProofStatus, PublicProofData, ZkFramework } from "@zk-email/sdk";
import { init, generateCircuitInputsWithDecomposedRegexesAndExternalInputs, parseEmail } from "../../pkg/relayer_utils.js";

const blueprintId = "acca28fd-753f-45ba-a14d-1ae32e1c4a41";

let relayerUtilsResolver: (value: any) => void;
const relayerUtilsInit: Promise<void> = new Promise((resolve) => {
  relayerUtilsResolver = resolve;
});

init()
  .then(() => {
    relayerUtilsResolver(null);
  })
  .catch((err) => {
    console.error("Failed to initialize wasm for relayer-utils: ", err);
  });


export function setupCircomProver(element: HTMLElement) {
  // const sdk = zkeSdk();
  const sdk = zkeSdk({
    baseUrl: "https://dev-conductor.zk.email",
    logging: { enabled: true, level: "debug" },
  });
  // const sdk = zkeSdk({
  //   baseUrl: "http://127.0.0.1:8080",
  //   logging: { enabled: true, level: "debug" },
  // });
  // const sdk = zkeSdk({ baseUrl: "https://dev-conductor.zk.email" });

  const proveButton = element.querySelector("button");
  if (proveButton) {
    proveButton.addEventListener("click", async () => {
      try {
        console.log("getting blueprint");
        const blueprint = await sdk.getBlueprintById(blueprintId);

        console.log("blueprint: ", blueprint);

        const prover = blueprint.createProver({isLocal: false});
        console.log("prover created");

        const eml = await getEml();

        try {
          const isValidEml = await blueprint.validateEmail(eml!);
          console.log("isValidEml: ", isValidEml);
        } catch (err) {
          console.error("Email is not valid: ", err);
        }

        const parsedEmail = await parseEmail(eml!);
        console.log("parsed email: ", !!parsedEmail);
        
        const externalInputs: ExternalInputInput[] = [];

        const params: GenerateProofInputsParams = {
          maxHeaderLength: blueprint.props.emailHeaderMaxLength || 256,
          maxBodyLength: blueprint.props.emailBodyMaxLength || 2560,
          ignoreBodyHashCheck: blueprint.props.ignoreBodyHashCheck || false,
          removeSoftLineBreaks: blueprint.props.removeSoftLinebreaks || true,
          shaPrecomputeSelector: blueprint.props.shaPrecomputeSelector,
        };
        
        const regexGraphs = await blueprint.getCircomRegexGraphs();
        
        const decomposedRegexesCleaned = blueprint.props.decomposedRegexes.map((dcr) => {
          const regexGraph = regexGraphs[`${dcr.name}_regex.json`];
          if (!regexGraph) {
            throw new Error(`No regexGraph was compiled for decomposedRegexe ${dcr.name}`);
          }

          let haystackLocation;
          if (dcr.location === "header") {
            haystackLocation = "header";
          } else {
            haystackLocation = "body";
          }
          console.log("dcr \n", dcr);

          const maxHaystackLength =
          dcr.location === "header"
            ? blueprint.props.emailHeaderMaxLength
            : blueprint.props.emailBodyMaxLength;
          
            if(!maxHaystackLength) return;

          return {
            name: dcr.name,
            haystackLocation,
            maxHaystackLength: maxHaystackLength,
            maxMatchLength: 64, // TODO: extract the length from the blueprint in the zk-email-sdk-js and pass it here
            regexGraphJson : JSON.stringify(regexGraph),
            parts: dcr.parts.map((p) => ({
              // @ts-ignore
              is_public: p.isPublic || !!p.is_public,
              // @ts-ignore
              regex_def: p.regexDef || !!p.regex_def,
              ...(p.isPublic && { maxLength: 20 }), // TODO same as above
            })),
            provingFramework: "circom",
          };
        });

        console.log("decomposedRegexesCleaned ", decomposedRegexesCleaned)

   
        const inputs = await generateCircuitInputsWithDecomposedRegexesAndExternalInputs(eml!, decomposedRegexesCleaned, externalInputs, params);
        
        console.log("inputs to the circuits\n", inputs);
        
        const circuitInputsObject: any = {};
        for (const [key, value] of inputs) {
          if (value && typeof value === "object" && value instanceof Map) {
            circuitInputsObject[key] = Object.fromEntries(value);
          } else if (value) {
            circuitInputsObject[key] = value;
          }
        }
        
        console.log("circuitInputsObject: ", circuitInputsObject);
        
        // ==================================================================================
        
        const proof = await prover.generateProof(eml!, externalInputs, { _inputs: JSON.stringify(circuitInputsObject) });
        console.log("proof: ", proof);
        
        return;
        
        // const [chunkedZkeyUrls, wasmUrl] = await Promise.all([
        //   blueprint.getChunkedZkeyDownloadLinks(),
        //   blueprint.getWasmFileDownloadLink(),
        // ]);
        // console.log("chunkedZkeyUrls: ", chunkedZkeyUrls);
        // console.log("wasmUrl: ", wasmUrl);
    
        // // Use the copied worker file directly instead of the string version
        // const worker = new Worker(new URL('./localProverWorker.js', import.meta.url), {
        //   type: 'module'
        // });
    
        // const { proof, publicSignals } = await new Promise<{
        //   proof: string;
        //   publicSignals: string[];
        //   publicData: string;
        // }>(async (resolve, reject) => {
        //   let publicData = "";
    
        //   worker.onmessage = (event) => {
        //     const { type, message, error } = event.data;
        //     switch (type) {
        //       case "progress":
        //         console.log(`Progress: ${message}`);
        //         break;
        //       case "message":
        //         console.log(message);
        //         break;
        //       case "result":
        //         message.publicData = publicData;
        //         resolve(message as { proof: string; publicSignals: string[]; publicData: string });
        //         break;
        //       case "error":
        //         console.error("Error in worker:", error);
        //         reject(error);
        //         break;
        //     }
        //   };
    
        //   worker.postMessage({
        //     chunkedZkeyUrls,
        //     inputs,
        //     wasmUrl,
        //     loggingConfig: { enabled: true, level: "debug" }
        //   });
        // });
    
        // const proofExternalInputs: ExternalInputProof = externalInputs.reduce(
        //   (acc: ExternalInputProof, cur) => {
        //     acc[cur.name] = cur.value;
        //     return acc;
        //   },
        //   {}
        // );
    
        // const proofProps: ProofProps = {
        //   id: "id-" + Math.random().toString(36).substring(2, 9),
        //   blueprintId: blueprint.props.id!,
        //   input: inputs,
        //   proofData: proof,
        //   publicData: parsePublicSignals(publicSignals, blueprint.props.decomposedRegexes),
        //   publicOutputs: publicSignals,
        //   externalInputs: proofExternalInputs,
        //   status: ProofStatus.Done,
        //   startedAt: startTime,
        //   provedAt: new Date(),
        //   isLocal: true,
        // };
       
        // console.log("proof successful: ", proofProps);
        
      } catch (err) {
        console.error("Failed to prove: ", err);
      }
    });
  }
}

async function getEml() {
  try {
    const response = await fetch("/github.eml"); // URL is relative to the root of the project
    if (!response.ok) {
      throw new Error("Network response was not ok " + response.statusText);
    }
    const data = await response.text(); // Get the content as text
    return data;
  } catch (error) {
    console.error("There has been a problem with your fetch operation:", error);
  }
}

function addMaxLengthToExternalInputs(
  externalInputs: ExternalInputInput[],
  externalInputDefinitions?: ExternalInput[]
) {
  const externalInputsWithMaxLength: (ExternalInputInput & { maxLength: number })[] = [];
  if (externalInputDefinitions) {
    for (const externalInputDefinition of externalInputDefinitions) {
      const externalInput = externalInputs.find((ei) => ei.name === externalInputDefinition.name);
      if (!externalInput) {
        throw new Error(`You must provide the external input for ${externalInputDefinition.name}`);
      }
      externalInputsWithMaxLength.push({
        ...externalInput,
        maxLength: externalInputDefinition.maxLength,
      });
    }
  }
  return externalInputsWithMaxLength;
}

function parseNoirPublicOutputs(
  publicOutputs: string[],
  decomposedRegexes: DecomposedRegex[],
  externalInputDefinition?: ExternalInput[],
  externalInputs?: ExternalInputInput[]
): { publicData: PublicProofData; externalInputsProof?: ExternalInputProof } {
  // 0: pubkey hash
  // 1: header_hash[0]
  // 2: header_hash[1]
  // 3: prover_address
  let publicOutputIterator = 4;

  const publicStruct: { [key: string]: string[] } = {};
  const result: { publicData: PublicProofData; externalInputsProof?: ExternalInputProof } = {
    publicData: publicStruct,
  };

  if (externalInputs) {
    const externalInputsWithMaxLength = addMaxLengthToExternalInputs(
      externalInputs,
      externalInputDefinition
    );

    result.externalInputsProof = {};
    externalInputsWithMaxLength.forEach((externalInput) => {
      const signalLength =
        Math.floor(externalInput.maxLength / 31) + (externalInput.maxLength % 31 !== 0 ? 1 : 0);
      publicOutputIterator += signalLength;
      result.externalInputsProof![externalInput.name] = externalInput.value;
    });
  }

  decomposedRegexes.forEach((decomposedRegex) => {
    const partOutputs: string[] = [];

    const { maxLength } = decomposedRegex;
    decomposedRegex.parts.forEach((part) => {
      if (decomposedRegex.isHashed) {
        partOutputs.push(publicOutputs[publicOutputIterator]);
        publicOutputIterator++;
      } else if (part.isPublic) {
        let partStr = "";
        for (let i = publicOutputIterator; i < publicOutputIterator + maxLength; i++) {
          const char = toUtf8(publicOutputs[i]);
          partStr += char;
        }
        partOutputs.push(partStr);
        publicOutputIterator += maxLength;
        // The next element is the length of the part
        const partLength = parseInt(publicOutputs[publicOutputIterator], 16);
        if (partStr.length !== partLength) {
          throw new Error("Length of part didn't match the given length output");
        }
        publicOutputIterator++;
      }
    });

    // Collect all part outputs for this decomposedRegex
    publicStruct[decomposedRegex.name] = partOutputs;
  });

  return result;
}

function toUtf8(hex: string): string {
  // Remove '0x' prefix and leading zeros
  const cleanHex = hex.slice(2).replace(/^0+/, "");

  // Convert the hex to a Uint8Array
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }

  // Use TextDecoder to convert to UTF-8
  return new TextDecoder().decode(bytes);
}

// Copied from sdk
async function generateProofInputsSdkCopy(
  eml: string,
  blueprint: Blueprint,
  externalInputs: ExternalInputInput[] = [],
): Promise<string> {

  const externalInputsWithMaxLength = addMaxLengthToExternalInputs(
    externalInputs,
    blueprint.props.externalInputs
  );

  let inputs: string;
  try {
    // TODO: Do we use defaults?
    const params: GenerateProofInputsParams = {
      emailHeaderMaxLength: blueprint.props.emailHeaderMaxLength || 256,
      emailBodyMaxLength: blueprint.props.emailBodyMaxLength || 2560,
      ignoreBodyHashCheck: blueprint.props.ignoreBodyHashCheck || false,
      removeSoftLinebreaks: blueprint.props.removeSoftLinebreaks || true,
      shaPrecomputeSelector: blueprint.props.shaPrecomputeSelector,
    };
    inputs = await generateProofInputs(
      eml,
      blueprint.props.decomposedRegexes,
      externalInputsWithMaxLength,
      params
    );

    console.log("got proof inputs: ", inputs);
  } catch (err) {
    console.error("Failed to generate inputs for proof");
    throw err;
  }

  return inputs;
}

export async function generateProofInputs(
  eml: string,
  decomposedRegexes: DecomposedRegex[],
  externalInputs: (ExternalInputInput & { maxLength: number })[],
  params: GenerateProofInputsParams
): Promise<string> {
  try {
    const internalParams: GenerateProofInputsParamsInternal = {
      maxHeaderLength: params.emailHeaderMaxLength,
      maxBodyLength: params.emailBodyMaxLength,
      ignoreBodyHashCheck: params.ignoreBodyHashCheck,
      removeSoftLineBreaks: params.removeSoftLinebreaks,
      shaPrecomputeSelector: params.shaPrecomputeSelector,
    };

    await relayerUtilsInit;

    const decomposedRegexesCleaned = decomposedRegexes.map((dcr) => {
      return {
        ...dcr,
        parts: dcr.parts.map((p) => ({
          // @ts-ignore
          is_public: p.isPublic || !!p.is_public,
          // @ts-ignore
          regex_def: p.regexDef || !!p.regex_def,
        })),
      };
    });

    console.log("calling generateCircuitInputsWithDecomposedRegexesAndExternalInputs");
    const inputs = await generateCircuitInputsWithDecomposedRegexesAndExternalInputs(
      eml,
      decomposedRegexesCleaned,
      externalInputs,
      internalParams
    );

    const json = JSON.stringify(Object.fromEntries(inputs));
    return json;
  } catch (err) {
    console.error("Failed to generate inputs for proof");
    throw err;
  }
}

// Parses public signals from a proof to readable outputs
// Translated from our existing go code internal/temporal/workflows/circom_workflows.go
export function parsePublicSignals(
  publicSignals: string[],
  decomposedRegexes: DecomposedRegex[]
): PublicProofData {
  let publicOutputIterator = 3; // like publicOutputIterator in Go
  const publicStruct: { [key: string]: string[] } = {};

  decomposedRegexes.forEach((decomposedRegex) => {
    let signalLength = 1;
    if (!decomposedRegex.isHashed) {
      signalLength = Math.ceil(decomposedRegex.maxLength / 31);
    }

    const partOutputs: string[] = [];

    decomposedRegex.parts.forEach((part) => {
      if (part.isPublic) {
        // Slice out the relevant subset from publicSignals
        const publicOutputsSlice = publicSignals.slice(
          publicOutputIterator,
          publicOutputIterator + signalLength
        );

        // Decode using the replicated Go logic
        let output = "";
        if (decomposedRegex.isHashed) {
          output = publicOutputsSlice + "";
        } else {
          output = processIntegers(publicOutputsSlice);
        }

        // Store the decoded result
        partOutputs.push(output);

        // Advance the iterator
        publicOutputIterator += signalLength;
      }
    });

    // Collect all part outputs for this decomposedRegex
    publicStruct[decomposedRegex.name] = partOutputs;
  });

  // Combine part outputs into final object
  return publicStruct;
}
