import zkeSdk, { DecomposedRegex, ExternalInput, ExternalInputInput, ExternalInputProof, parseEmail, PublicProofData } from "@zk-email/sdk";
import { initNoirWasm } from "@zk-email/sdk/initNoirWasm";
import { init, generateNoirCircuitInputsWithRegexesAndExternalInputs } from "../../pkg/relayer_utils.js";

export function setupNoirProver(element: HTMLElement) {
  const sdk = zkeSdk({
    baseUrl: "https://staging-conductor.zk.email",
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
        // const blueprint = await sdk.getBlueprintById("4c67a6fe-6202-40ff-8672-9dbe02e5cb52");
        const blueprint = await sdk.getBlueprintById("b31e09ef-86fa-4a70-a062-e016a8780af8");

        console.log("blueprint: ", blueprint);

        const prover = blueprint.createProver({ isLocal: true });
        console.log("prover");
        console.log("typeof prover", typeof prover);

        const eml = await getEml();

        try {
          const isValidEml = await blueprint.validateEmail(eml!);
          console.log("isValidEml: ", isValidEml);
        } catch (err) {
          console.error("Email is not valid: ", err);
        }

        const { Noir, UltraHonkBackend } = await initNoirWasm();
        
        // Initialize relayer-utils WASM
        await init();
        
        const parsedEmail = await parseEmail(eml!);
        
        const circuit = await blueprint.getNoirCircuit();
        const regexGraphs = await blueprint.getNoirRegexGraphs();
        
        const regexInputs = blueprint.props.decomposedRegexes.map((dr) => {
          const regexGraph = regexGraphs[`${dr.name}_regex.json`];
          if (!regexGraph) {
            throw new Error(`No regexGraph was compiled for decomposedRegexe ${dr.name}`);
          }
    
          // const haystack =
          //   dr.location === "header" ? parsedEmail.canonicalizedHeader : parsedEmail.cleanedBody;
    
          let haystack;
          if (dr.location === "header") {
            haystack = parsedEmail.canonicalizedHeader;
          } else if (blueprint.props.shaPrecomputeSelector) {
            haystack = parsedEmail.cleanedBody.split(blueprint.props.shaPrecomputeSelector)[1];
          } else {
            haystack = parsedEmail.cleanedBody;
          }
    
          const maxHaystackLength =
            dr.location === "header"
              ? blueprint.props.emailHeaderMaxLength
              : blueprint.props.emailBodyMaxLength;
    
          return {
            name: dr.name,
            regex_graph_json: JSON.stringify(regexGraph),
            haystack,
            max_haystack_length: maxHaystackLength,
            max_match_length: dr.maxLength,
            proving_framework: "noir",
          };
        });
    
        const noirParams = {
          maxHeaderLength: blueprint.props.emailHeaderMaxLength || 512,
          maxBodyLength: blueprint.props.emailBodyMaxLength || 0,
          ignoreBodyHashCheck: blueprint.props.ignoreBodyHashCheck,
          removeSoftLineBreaks: blueprint.props.removeSoftLinebreaks,
          shaPrecomputeSelector: blueprint.props.shaPrecomputeSelector,
          proverEthAddress: "0x0000000000000000000000000000000000000000",
        };
    
        console.log("generating inputs regexInputs: ", regexInputs);
        // console.log("generating inputs externalInputs: ", externalInputs);
        console.log("generating inputs noirParams: ", noirParams);
    
        const externalInputsWithMaxLength = addMaxLengthToExternalInputs(
          [],
          blueprint.props.externalInputs
        );
    
        console.log("externalInputsWithMaxLength: ", externalInputsWithMaxLength);
    
        const circuitInputs = await generateNoirCircuitInputsWithRegexesAndExternalInputs(
          eml,
          regexInputs,
          externalInputsWithMaxLength,
          noirParams
        );
        console.log("circuitInputs: ", circuitInputs);
    
        console.log("circuitInputs: ", circuitInputs);
    
        if (!circuitInputs) {
          throw new Error("Could not generate circuit inputs for noir");
        }
    
        const compiledProgram = circuit as any;
    
        const noir = new Noir(compiledProgram);
        // TODO: we can use threads here, although not defining threads is the same speed
        // const backend = new UltraHonkBackend(circuit.bytecode, threads ? { threads } : {});
        const backend = new UltraHonkBackend(compiledProgram.bytecode);
    
        // Convert from Map to object
        const circuitInputsObject: any = {};
        for (const [key, value] of circuitInputs) {
          if (value && typeof value === "object" && value instanceof Map) {
            circuitInputsObject[key] = Object.fromEntries(value);
          } else if (value) {
            circuitInputsObject[key] = value;
          }
        }
    
        console.log("circuitInputsObject: ", circuitInputsObject);
        // delete circuitInputsObject.dkim_header_sequence;
    
        console.time("witness");
        const { witness } = await noir.execute(circuitInputsObject);
        console.timeEnd("witness");
    
        console.time("prove");
        const proof = await backend.generateProof(witness);
        console.timeEnd("prove");
    
        const { publicData, externalInputsProof } = parseNoirPublicOutputs(
          proof.publicInputs,
          blueprint.props.decomposedRegexes,
          blueprint.props.externalInputs,
          externalInputsWithMaxLength
        );
        
        console.log("publicData: ", publicData);
        console.log("externalInputsProof: ", externalInputsProof);
        
      } catch (err) {
        console.error("Failed to prove: ", err);
      }
    });
  }
}

async function getEml() {
  try {
    const response = await fetch("/x.eml"); // URL is relative to the root of the project
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
