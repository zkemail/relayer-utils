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
const utils = require("../../utils");
const ff = require('ffjavascript');
const stringifyBigInts = ff.utils.stringifyBigInts;
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const path = __importStar(require("path"));
const p = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const field = new ff.F1Field(p);
const emailWalletUtils = require("../../utils");
const option = {
    include: path.join(__dirname, "../../../node_modules")
};
const claim_1 = require("../helpers/claim");
// const grumpkin = require("circom-grumpkin");
jest.setTimeout(120000);
describe("Claim", () => {
    it("claim an unclaimed funds/states", async () => {
        const emailAddr = "suegamisora@gmail.com";
        const emailAddrRand = emailWalletUtils.emailAddrCommitRand();
        const accountKey = emailWalletUtils.genAccountKey();
        const circuitInputs = await (0, claim_1.genClaimInput)(emailAddr, emailAddrRand, accountKey);
        const circuit = await wasm_tester(path.join(__dirname, "../src/claim.circom"), option);
        const witness = await circuit.calculateWitness(circuitInputs);
        await circuit.checkConstraints(witness);
        const expectedEmailAddrCommit = emailWalletUtils.emailAddrCommit(emailAddr, emailAddrRand);
        expect(BigInt(expectedEmailAddrCommit)).toEqual(witness[1]);
        const walletSalt = emailWalletUtils.walletSalt(emailAddr, accountKey);
        expect(BigInt(walletSalt)).toEqual(witness[2]);
    });
});
