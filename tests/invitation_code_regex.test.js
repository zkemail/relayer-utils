"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const path = __importStar(require("path"));
const emailWalletUtils = require("../../utils");
const option = {
    include: path.join(__dirname, "../../../node_modules")
};
// const grumpkin = require("circom-grumpkin");
jest.setTimeout(120000);
describe("Invitation Code Regex", () => {
    it("invitation code", async () => {
        const codeStr = "Code 123abc";
        // const prefixLen = "ACCOUNTKEY.0x".length;
        // const revealed = "123abc";
        const paddedStr = emailWalletUtils.padString(codeStr, 256);
        const circuitInputs = {
            msg: paddedStr,
        };
        const circuit = await wasm_tester(path.join(__dirname, "./circuits/test_invitation_code_regex.circom"), option);
        const witness = await circuit.calculateWitness(circuitInputs);
        await circuit.checkConstraints(witness);
        // console.log(witness);
        expect(1n).toEqual(witness[1]);
        const prefixIdxes = emailWalletUtils.extractInvitationCodeIdxes(codeStr)[0];
        for (let idx = 0; idx < 256; ++idx) {
            if (idx >= prefixIdxes[0] && idx < prefixIdxes[1]) {
                expect(BigInt(paddedStr[idx])).toEqual(witness[2 + idx]);
            }
            else {
                expect(0n).toEqual(witness[2 + idx]);
            }
        }
    });
    it("invitation code in the subject", async () => {
        const codeStr = "Send 0.1 ETH to alice@gmail.com code 123abc";
        // const prefixLen = "sepolia+ACCOUNTKEY.0x".length;
        // const revealed = "123abc";
        const paddedStr = emailWalletUtils.padString(codeStr, 256);
        const circuitInputs = {
            msg: paddedStr,
        };
        const circuit = await wasm_tester(path.join(__dirname, "./circuits/test_invitation_code_regex.circom"), option);
        const witness = await circuit.calculateWitness(circuitInputs);
        await circuit.checkConstraints(witness);
        // console.log(witness);
        expect(1n).toEqual(witness[1]);
        const prefixIdxes = emailWalletUtils.extractInvitationCodeIdxes(codeStr)[0];
        // const revealedStartIdx = emailWalletUtils.extractSubstrIdxes(codeStr, readFileSync(path.join(__dirname, "../src/regexes/invitation_code.json"), "utf8"))[0][0];
        // console.log(emailWalletUtils.extractSubstrIdxes(codeStr, readFileSync(path.join(__dirname, "../src/regexes/invitation_code.json"), "utf8")));
        for (let idx = 0; idx < 256; ++idx) {
            if (idx >= prefixIdxes[0] && idx < prefixIdxes[1]) {
                expect(BigInt(paddedStr[idx])).toEqual(witness[2 + idx]);
            }
            else {
                expect(0n).toEqual(witness[2 + idx]);
            }
        }
    });
    it("invitation code in the email address", async () => {
        const codeStr = "sepolia+code123456@sendeth.org";
        // const prefixLen = "sepolia+ACCOUNTKEY.0x".length;
        // const revealed = "123abc";
        const paddedStr = emailWalletUtils.padString(codeStr, 256);
        const circuitInputs = {
            msg: paddedStr,
        };
        const circuit = await wasm_tester(path.join(__dirname, "./circuits/test_invitation_code_regex.circom"), option);
        const witness = await circuit.calculateWitness(circuitInputs);
        await circuit.checkConstraints(witness);
        // console.log(witness);
        expect(1n).toEqual(witness[1]);
        const prefixIdxes = emailWalletUtils.extractInvitationCodeIdxes(codeStr)[0];
        // const revealedStartIdx = emailWalletUtils.extractSubstrIdxes(codeStr, readFileSync(path.join(__dirname, "../src/regexes/invitation_code.json"), "utf8"))[0][0];
        // console.log(emailWalletUtils.extractSubstrIdxes(codeStr, readFileSync(path.join(__dirname, "../src/regexes/invitation_code.json"), "utf8")));
        for (let idx = 0; idx < 256; ++idx) {
            if (idx >= prefixIdxes[0] && idx < prefixIdxes[1]) {
                expect(BigInt(paddedStr[idx])).toEqual(witness[2 + idx]);
            }
            else {
                expect(0n).toEqual(witness[2 + idx]);
            }
        }
    });
});
