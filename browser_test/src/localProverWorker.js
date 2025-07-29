import localforage from "localforage";
import * as snarkjs from "@zk-email/snarkjs";
import pako from "pako";

const circuitName = "circuit";

// Simple logger for web worker that respects the parent's logging configuration
let loggingEnabled = false;
const logger = {
  info: (...args) => {
    if (loggingEnabled) console.log(...args);
  },
  debug: (...args) => {
    if (loggingEnabled) console.log(...args);
  }
};

async function downloadWithRetries(link, downloadAttempts) {
  for (let i = 1; i <= downloadAttempts; i++) {
    logger.debug(`download attempt ${i} for ${link}`);
    const response = await fetch(link, { method: "GET" });
    if (response.status === 200) {
      return response;
    }
  }
  throw new Error(`Error downloading ${link} after ${downloadAttempts} retries`);
}

// uncompresses single .gz file.
// returns the contents as an ArrayBuffer
export const uncompressGz = async (arrayBuffer) => {
  const output = pako.ungzip(arrayBuffer);
  const buff = output.buffer;
  return buff;
};

// GET the compressed file from the remote server, then store it with localforage
// Note that it must be stored as an uncompressed ArrayBuffer
// and named such that filename===`${name}.zkey${a}` in order for it to be found by snarkjs.
export async function downloadFromUrl(fileUrl, targetFileName, compressed = false) {
  const fileResp = await downloadWithRetries(fileUrl, 3);

  const buff = await fileResp.arrayBuffer();
  if (!compressed) {
    await localforage.setItem(targetFileName, buff);
  } else {
    // uncompress the data
    const fileUncompressed = await uncompressGz(buff);
    await localforage.setItem(targetFileName, fileUncompressed);
    logger.debug("stored file in localforage", targetFileName);
  }
  logger.info(`Storage of ${targetFileName} successful!`);
}

self.onmessage = async function (event) {
  const { chunkedZkeyUrls, inputs, wasmUrl, loggingConfig } = event.data;
  
  // Configure logging based on parent's settings
  if (loggingConfig) {
    loggingEnabled = loggingConfig.enabled && loggingConfig.level !== 'silent';
  }

  self.postMessage({ type: "message", message: "Worker started" });
  self.postMessage({ type: "progress", message: "Downloading zkeys" });

  // Download each chunk individually - snarkjs will find them automatically
  await Promise.all(
    chunkedZkeyUrls.map(async ({ suffix, url }) => {
      await downloadFromUrl(url, `${circuitName}.zkey${suffix}`, true);
    })
  );
  self.postMessage({ type: "message", message: "Download complete" });

  try {
    self.postMessage({ type: "progress", message: "Proving" });
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      JSON.parse(inputs),
      wasmUrl,
      `${circuitName}.zkey`
    );

    await localforage.clear();
    self.postMessage({ type: "result", message: { proof, publicSignals } });

    // const result = await verifyProof(proof, publicSignals, filesUrl, circuitName);

    // self.postMessage({ type: "result", result });

    logger.info("shutting down worker");
    self.close(); // Shut down the worker
  } catch (error) {
    // @ts-ignore
    self.postMessage({ type: "error", error: error.message });
    self.close(); // Shut down on error
  }
};