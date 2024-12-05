const fs = require('fs');
const path = require('path');

const pkgDir = path.join(__dirname, 'pkg');
const wasmFile = path.join(pkgDir, 'relayer_utils_bg.wasm');
const jsFile = path.join(pkgDir, 'relayer_utils.js');
const typesFile = path.join(pkgDir, 'relayer_utils.d.ts');
const packageJsonFile = path.join(pkgDir, 'package.json');

const wasmBase64 = fs.readFileSync(wasmFile).toString('base64');

let jsCode = fs.readFileSync(jsFile, 'utf8');

// Remove the import statement for the .wasm file
jsCode = jsCode.replace(
  /import\s+\*\s+as\s+wasm\s+from\s+['"]\.\/relayer_utils_bg\.wasm['"];\s*/g,
  ''
);

// Insert code to instantiate the wasm module from the base64 string
const wasmInitCode = `
import * as wasm_bindgen from "./relayer_utils_bg.js";
import { __wbg_set_wasm } from "./relayer_utils_bg.js";

const wasmBase64 = '${wasmBase64}';
// Don't use Buffer for browser compatibility
// Decode the base64 string into a binary string
const binaryString = atob(wasmBase64);

// Convert the binary string into a Uint8Array
const wasmBytes = new Uint8Array(binaryString.length);
for (let i = 0; i < binaryString.length; i++) {
    wasmBytes[i] = binaryString.charCodeAt(i);
}

let wasm;

async function init() {
  const imports = {};
  imports['./relayer_utils_bg.js'] = wasm_bindgen;

  const wasmModule = await WebAssembly.instantiate(wasmBytes, imports);
  wasm = wasmModule.instance.exports;
  __wbg_set_wasm(wasm);
  if (wasm.__wbindgen_start) {
    wasm.__wbindgen_start();
  }
}

export { init };
export * from "./relayer_utils_bg.js";
`;

jsCode = wasmInitCode;

// Write the modified JavaScript code back to relayer_utils.js
fs.writeFileSync(jsFile, jsCode);

const packageJsonBase = fs.readFileSync(path.join(__dirname, 'package.json')).toString();
const packageJsonBaseParsed = JSON.parse(packageJsonBase);

const packageJson = `
  {
    "name": "${packageJsonBaseParsed.name}",
    "type": "module",
    "collaborators": [
      "Sora Suegami",
      "Aditya Bisht"
    ],
    "version": "${packageJsonBaseParsed.version}",
    "license": "MIT",
    "files": [
      "relayer_utils_bg.wasm",
      "relayer_utils.js",
      "relayer_utils_bg.js",
      "relayer_utils.d.ts"
    ],
    "main": "relayer_utils.js",
    "types": "relayer_utils.d.ts",
    "sideEffects": [
      "./relayer_utils.js",
      "./snippets/*"
    ]
  }
`

fs.writeFileSync(packageJsonFile, packageJson);

let typesCode = fs.readFileSync(typesFile, 'utf8');
typesCode += `/**
 * Initializes wasm module, call this once before using functions of the package.
 * @returns {Promise<void>}
 */
export async function init(): Promise<void>;
`

fs.writeFileSync(typesFile, typesCode);
