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
const account_creation_1 = require("../helpers/account_creation");
const fs_1 = require("fs");
const circom_grumpkin_1 = require("circom-grumpkin");
jest.setTimeout(2080000);
describe("Account Initialization", () => {
    it("init an account", async () => {
        const emailFilePath = path.join(__dirname, "./emails/account_creation_test1.eml");
        const emailRaw = (0, fs_1.readFileSync)(emailFilePath, "utf8");
        const parsedEmail = await emailWalletUtils.parseEmail(emailRaw);
        const relayerRand = emailWalletUtils.genRelayerRand();
        const circuitInputs = await (0, account_creation_1.genAccountCreationInput)(emailFilePath, relayerRand);
        const circuit = await wasm_tester(path.join(__dirname, "../src/account_creation.circom"), option);
        const witness = await circuit.calculateWitness(circuitInputs);
        await circuit.checkConstraints(witness);
        const domainName = "gmail.com";
        const paddedDomain = emailWalletUtils.padString(domainName, 255);
        const domainFields = emailWalletUtils.bytes2Fields(paddedDomain);
        for (let idx = 0; idx < domainFields.length; ++idx) {
            expect(BigInt(domainFields[idx])).toEqual(witness[1 + idx]);
        }
        const expectedPubKeyHash = emailWalletUtils.publicKeyHash(parsedEmail.publicKey);
        expect(BigInt(expectedPubKeyHash)).toEqual(witness[10]);
        const expectedEmailNullifier = emailWalletUtils.emailNullifier(parsedEmail.signature);
        expect(BigInt(expectedEmailNullifier)).toEqual(witness[11]);
        const timestamp = 1707866192n;
        expect(timestamp).toEqual(witness[12]);
        const emailAddr = "suegamisora@gmail.com";
        const accountKey = "0x01eb9b204cc24c3baee11accc37d253a9c53e92b1a2cc07763475c135d575b76";
        const expectedWalletSalt = emailWalletUtils.walletSalt(emailAddr, accountKey);
        expect(BigInt(expectedWalletSalt)).toEqual(witness[13]);
        const hashedPoint = (0, circom_grumpkin_1.hash_to_curve)(emailWalletUtils.padEmailAddr(emailAddr));
        const expectedPsiPoint = (0, circom_grumpkin_1.point_scalar_mul)(hashedPoint.x, hashedPoint.y, BigInt(relayerRand));
        expect(expectedPsiPoint.x).toEqual(witness[14]);
        expect(expectedPsiPoint.y).toEqual(witness[15]);
    });
});
