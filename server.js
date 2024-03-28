const express = require('express');
const ethers = require('ethers');
const socketio = require("socket.io-client");
const forwarderABI = require("./contracts/forwarderABI.json");
const tradingABI = require("./contracts/tradingABI.json");
const optionsABI = require("./contracts/optionsABI.json");
const arbgasABI = require("./contracts/arbgasABI.json");
const cors = require('cors');
const https= require("https")
const fs= require("fs");
const {getBigInt, formatEther} = require("ethers");

require('dotenv').config();

const sslOptions = {
    key: process.env.SSL_KEY_PATH && fs.readFileSync(process.env.SSL_KEY_PATH),
    cert: process.env.SSL_CERT_PATH && fs.readFileSync(process.env.SSL_CERT_PATH)
};

const EMPTY_PRICE_DATA = ["0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE", false, 0, 0, 0, 0, ethers.zeroPadBytes("0x", 65)];

class App {

    constructor() {

        this.forwarderAddress = {
            42161: "0xEC75cf9a18eF82Fa7F8F2A7afAf2521cD998D757",
            137: "0x17eE6D3ec827863119698D125EFB3200B49e90c6",
            82: "0x71B3EdDD0628875C22ec49D8D1E0eEE20759945E"
        };
        this.tradingAddress = {
            42161: "0xd89B4B1C8918150f137cc68E83E3876F9e309aB9",
            137: "0xA35eabB4be62Ed07E88c2aF73234fe7dD48a73D4",
            82: "0xD1705f847b421b6C0bb31e649fBA1983257B77D3"
        }
        this.optionsAddress = {
            42161: "0x8895b0B946b3d5bCd7D1E9E31DCfaeB51644922A",
            137: "0xFeABeC2CaC8A1A2f1C0c181572aA88c8b91288B2",
            82: "0xDa3662a982625e1f2649b0a1e571207C0D87B76E"
        }
        this.gasLimits = {
            42161: 3000000,
            137: 1500000,
            82: 1100000
        }

        this.rpcs = {
            42161: process.env.ARBITRUM_RPC_URL,
            137: process.env.POLYGON_RPC_URL,
            82: process.env.METER_RPC_URL
        }

        this.publicRpcs = {
            42161: "https://arb1.arbitrum.io/rpc",
            137: "https://polygon-rpc.com",
            82: "https://rpc.meter.io"
        }

        this.privs = [
            process.env[`PRIVATE_KEY_0`],
            process.env[`PRIVATE_KEY_1`],
            process.env[`PRIVATE_KEY_2`],
            process.env[`PRIVATE_KEY_3`],
            process.env[`PRIVATE_KEY_4`],
            process.env[`PRIVATE_KEY_5`],
            process.env[`PRIVATE_KEY_6`],
            process.env[`PRIVATE_KEY_7`],
            process.env[`PRIVATE_KEY_8`],
            process.env[`PRIVATE_KEY_9`],
        ];

        this.name = process.env.DISPLAY_NAME;

        this.publics = [];
        for (let i = 0; i < this.privs.length; i++) {
            this.publics.push(new ethers.Wallet(this.privs[i]).address);
        }

        // Check that all private keys are set
        for (let i = 0; i < this.privs.length; i++) {
            if (this.privs[i] === undefined) {
                throw new Error(`MISSING PRIVATE KEY #${i}.\nSET IT IN THE ".env" FILE USING PRIVATE_KEY_${i}=<private_key>.\n10 PRIVATE KEYS (0-9) ARE REQUIRED.\n`);
            }
        }

        if (process.env["POLYGON_RPC_URL"] === undefined) {
            throw new Error(`MISSING POLYGON RPC URL.\nSET IT IN THE ".env" FILE USING POLYGON_RPC_URL=<polygon_rpc_url>.\n`);
        }

        if (process.env["ARBITRUM_RPC_URL"] === undefined) {
            throw new Error(`MISSING ARBITRUM RPC URL.\nSET IT IN THE ".env" FILE USING ARBITRUM_RPC_URL=<arbitrum_rpc_url>.\n`);
        }

        if (process.env["METER_RPC_URL"] === undefined) {
            throw new Error(`MISSING METER RPC URL.\nSET IT IN THE ".env" FILE USING METER_RPC_URL=<meter_rpc_url>.\n`);
        }

        if (process.env["DISPLAY_NAME"] === undefined) {
            throw new Error(`MISSING DISPLAY NAME.\nSET IT IN THE ".env" FILE USING DISPLAY_NAME=<name>.\n`);
        }

        // Log all the addresses
        for (let i = 0; i < this.privs.length; i++) {
            console.log(`Relayer #${i}: ${new ethers.Wallet(this.privs[i]).address}`);
        }

        this.app = express().use(function (req, res, next) {
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
            res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');
            res.setHeader('Access-Control-Allow-Credentials', true);
            next();
        })

        // Init Middlewares
        this.app.use(express.json({ limit: "5kb" }));
        this.app.use(cors());

        const PORT = process.env.PORT || 8000;

        this.app.listen(PORT, () => {
            console.log(`INFO: Server started on port ${PORT}`);
        });

        if (
            sslOptions.key !== undefined &&
            sslOptions.cert !== undefined
        ) {
            https.createServer(sslOptions, this.app).listen(443);
        }

        this.app.get("/name", async (req, res) => {
            if (this.isGettingReady) {
                res.status(503).json({ reason: "Node not ready yet!" });
                return;
            }
            res.status(200).json(this.name);
        });

        this.app.get("/addresses", async (req, res) => {
            if (this.isGettingReady) {
                res.status(503).json({ reason: "Node not ready yet!" });
                return;
            }
            res.status(200).json(this.publics);
        });

        this.app.get("/health", async (req, res) => {
            if (this.isGettingReady) {
                res.status(503).json({ reason: "Node not ready yet!" });
                return;
            }
            if (this.lastPriceTimestamp + 1000 < Date.now()) {
                res.status(503).json({ reason: "Disconnected" });
                return;
            }
            if (this.gasBalances[42161] < 0.02 || this.gasBalances[137] < 5) {
                res.status(503).json({ reason: "Low on gas" });
                return;
            }
            if (req.query.timestamp) {
                res.status(200).json({ message: "OK", timestamp: req.query.timestamp });
            } else {
                res.status(200).json({ message: "OK" });
            }
        });

        this.app.get("/gas", async (req, res) => {
            if (this.isGettingReady) {
                res.status(503).json({ reason: "Node not ready yet!" });
                return;
            }
            res.status(200).json(this.accountGasBalance);
        });

        this.app.get("/gasRequirement", async (req, res) => {
            if (this.isGettingReady) {
                res.status(503).json({ reason: "Node not ready yet!" });
                return;
            }
            if (req.query.chainId) {
                if (!this.gasLimits[req.query.chainId]) {
                    res.status(400).json({ reason: "Unsupported chain ID!" });
                } else {
                    const {gasNeeded} = await this.getGasRequirement(Number(req.query.chainId));
                    res.status(200).json(formatEther(gasNeeded));
                }
            } else {
                res.status(400).json({ reason: "Chain ID not provided!" });
            }
        });

        this.oracleSocket = socketio(
            new Date().getTimezoneOffset() > 120 ?
                'https://us1.tigrisoracle.net' :
                'https://eu1.tigrisoracle.net',
            {transports: ['websocket'] }
        );

        this.oracleSocket.on('error', (error) => {
            console.log('ORACLE ERROR:\n', error);
        });

        this.oracleSocket.on('connect', () => {
            console.log('INFO: Oracle connected');
        });

        this.oracleSocket.on('disconnect', () => {
            console.log('WARNING: Oracle disconnected');
        });

        this.oracleSocket.on('data', (data) => {
            this.latestPriceData = data;
            this.lastPriceTimestamp = Date.now();
        });

        this.app.post('/execute', async (req, res) => {
            if (this.isGettingReady) {
                res.status(503).json({reason: "Node not ready yet!"});
                return;
            }
            if (this.gasBalances[42161] < 0.02 || this.gasBalances[137] < 5 || this.gasBalances[82] < 1) {
                res.status(503).json({reason: "Node low on gas!"});
                return;
            }
            // Check that request has only the required fields
            if (
                !req.body.hasOwnProperty("from") ||
                !req.body.hasOwnProperty("to") ||
                !req.body.hasOwnProperty("salt") ||
                !req.body.hasOwnProperty("deadline") ||
                !req.body.hasOwnProperty("data") ||
                !req.body.hasOwnProperty("signature") ||
                !req.body.hasOwnProperty("orderType") ||
                !req.body.hasOwnProperty("chainId")
            ) {
                res.status(400).json({reason: "Data missing in request!"});
                return;
            }
            // Check that orderType is valid
            if (
                // Leverage
                req.body.orderType !== "marketOpen" &&
                req.body.orderType !== "marketClose" &&
                req.body.orderType !== "createLimitOrder" &&
                req.body.orderType !== "addToPosition" &&
                req.body.orderType !== "addMargin" &&
                req.body.orderType !== "removeMargin" &&
                req.body.orderType !== "cancelLimitOrder" &&
                req.body.orderType !== "updateTpSl" &&
                // Options
                req.body.orderType !== "openTrade" &&
                req.body.orderType !== "initiateLimitOrder"
            ) {
                res.status(400).json({reason: "Unknown order type!"});
                return;
            }
            // Check that chainId is valid
            if (req.body.chainId !== 42161 && req.body.chainId !== 137 && req.body.chainId !== 82) {
                res.status(400).json({reason: "Unsupported chain ID!"});
                return;
            }
            // Check that deadline is not in the past
            if (req.body.deadline < Math.ceil(Date.now() / 1000)) {
                res.status(400).json({reason: "Request deadline passed!"});
                return;
            }
            if (
                req.body.to !== this.tradingAddress[req.body.chainId] &&
                req.body.to !== this.optionsAddress[req.body.chainId]
            ) {
                res.status(400).json({reason: "Invalid contract address!"});
                return;
            }
            if (req.body.pairId) {
                if (!this.latestPriceData[req.body.pairId]) {
                    res.status(400).json({reason: "Unknown pair ID!"});
                    return;
                } else {
                    if (this.latestPriceData[req.body.pairId].is_closed) {
                        res.status(400).json({reason: "Market is closed!"});
                        return;
                    }
                }
            }
            // Check that signature is valid
            if (!(await this.verifySignature(req.body))) {
                res.status(400).json({reason: "User signature verification failed!"});
                return;
            }
            // Check that function call is valid by matching it in the ABI
            if (!this.checkAbi(req.body.data, req.body.orderType)) {
                res.status(400).json({reason: "Request data does not match ABI!"});
                return;
            }
            // Check chain state
            const state = await this.validateState(req.body);
            if (!state.valid) {
                res.status(400).json({reason: state.reason});
                return;
            }
            const orderType = req.body.orderType;
            const request = [
                req.body.from,
                req.body.to,
                req.body.salt,
                req.body.deadline,
                req.body.data
            ];
            const signature = req.body.signature;
            const result = await this.execute(request, signature, orderType, req.body.chainId, req.body.pairId, state.gasLimit);
            if (!result.reason) {
                res.status(200).json(result);
            } else {
                res.status(400).json(result);
            }
        });

        this.isGettingReady = true;
        this.providers = {};
        this.publicProviders = {};
        this.signers = {};
        this.forwarderContract = {};
        this.nonces = {};
        this.gasBalances = {};
        this.accountGasBalance = {};
        this.arbgas = {};
        this.keyIndex = 0;
        this.setup();
        this.updateGasPriceInterval = setInterval(() => {
            this.updateGasPrice();
        }, 4000);
        this.updateGasBalancesInterval = setInterval(() => {
            this.updateGasBalance();
        }, 60000);
        this.updateNonceInterval = setInterval(() => {
            this.updateNonces();
        }, 60000);
    }

    checkAbi(data, orderType) {
        let contractInterface;
        if (
            orderType === "openTrade" ||
            orderType === "initiateLimitOrder"
        ) {
            contractInterface = new ethers.Interface(optionsABI);
        } else {
            contractInterface = new ethers.Interface(tradingABI);
        }

        let EMPTY_PRICE_DATA_BYTES = ethers.AbiCoder.defaultAbiCoder().encode(
            ["tuple(address,bool,uint256,uint256,uint256,uint256,bytes)"],
            [EMPTY_PRICE_DATA]
        );

        const dataLengthInBytes = (data.length + 56) / 2 - 1;
        const dataLength = ethers.zeroPadValue(ethers.toBeHex(dataLengthInBytes), 32);

        EMPTY_PRICE_DATA_BYTES = dataLength + EMPTY_PRICE_DATA_BYTES.slice(66);

        const concatData = data + EMPTY_PRICE_DATA_BYTES.slice(2);

        try {
            contractInterface.decodeFunctionData(orderType, concatData);
            return true;
        } catch (err) {
            console.log(err.reason ?? err.message);
            return false;
        }
    }

    async updateGasPrice() {
        try {
            this.gasData = {
                1: Math.floor(Number((await this.arbgas.getL1BaseFeeEstimate()))),
                42161: Math.floor(Number((await this.providers[42161].provider.getFeeData()).gasPrice)*1.3),
                137: Math.floor(Number((await this.providers[137].provider.getFeeData()).gasPrice)*3),
                82: Math.floor(Number((await this.providers[82].provider.getFeeData()).gasPrice)*1.1)
            }
        } catch(err) {
            console.log(err);
        }
    }

    async updateGasBalance() {
        try {
            for (const chainId of [42161, 137, 82]) {
                let minGasBalance = 1000000;
                for (const account in this.signers[chainId]) {
                    const address = await this.signers[chainId][account].getAddress();
                    let balance =
                        ethers.formatEther(
                            await this.providers[chainId].getBalance(address)
                        );
                    this.accountGasBalance[chainId][address] = balance;
                    balance = Number(balance);
                    if (chainId === 42161) {
                        if (balance < 0.02) {
                            console.log("WARNING: Address " + address + " is running low on gas on ARBITRUM! Only " + balance + " ETH left!");
                        }
                    } else if (chainId === 137) {
                        if (balance < 5) {
                            console.log("WARNING: Address " + address + " is running low on gas on POLYGON! Only " + balance + " MATIC left!");
                        }
                    } else if (chainId === 82) {
                        if (balance < 1) {
                            console.log("WARNING: Address " + address + " is running low on gas on METER! Only " + balance + " MTR left!");
                        }
                    }
                    if (balance < minGasBalance) {
                        minGasBalance = balance;
                    }
                }
                if (chainId === 137) {
                    if (this.gasBalances[chainId] < 5 && minGasBalance >= 10) {
                        console.log("INFO: Gas balance on POLYGON has recovered!");
                    }
                } else if (chainId === 42161) {
                    if (this.gasBalances[chainId] < 0.02 && minGasBalance >= 0.02) {
                        console.log("INFO: Gas balance on ARBITRUM has recovered!");
                    }
                } else if (chainId === 82) {
                    if (this.gasBalances[chainId] < 1 && minGasBalance >= 1) {
                        console.log("INFO: Gas balance on METER has recovered!");
                    }
                }
                this.gasBalances[chainId] = minGasBalance;
            }
        } catch(err) {
            console.log(err.reason ?? err.message);
        }
    }

    async updateNonces() {
        for (const chainId of [42161, 137, 82]) {
            for (const account in this.signers[chainId]) {
                try {
                const address = await this.signers[chainId][account].getAddress();
                this.nonces[chainId][address] = await this.providers[chainId].getTransactionCount(address);
                } catch(err) {
                    console.log(err.reason ?? err.message);
                }
            }
        }
    }

    async setup() {
        console.log("INFO: Setting up node...");
        setTimeout(() => {
            console.log("INFO: Do not interact with the node until it has finished setting up...");
        }, 2000);
        const networkIds = [42161, 137, 82];
        this.arbgas = new ethers.Contract("0x000000000000000000000000000000000000006C", arbgasABI, new ethers.JsonRpcProvider(this.rpcs[42161]));
        for (const chainId of networkIds) {
            this.forwarderContract[chainId] = {};
            this.accountGasBalance[chainId] = {};

            let rpc = this.rpcs[chainId];
            let publicRpc = this.publicRpcs[chainId];
            this.providers[chainId] = new ethers.JsonRpcProvider(rpc);
            this.publicProviders[chainId] = new ethers.JsonRpcProvider(publicRpc);
            const provider = this.providers[chainId];
            this.nonces[chainId] = {};
            this.signers[chainId] = {};

            for(let accounts=0; accounts<10; accounts++) {
                this.forwarderContract[chainId][accounts] = {};
                const privateKey = this.privs[accounts];
                const signer = new ethers.Wallet(privateKey, provider);
                this.signers[chainId][accounts] = signer;
                this.nonces[chainId][accounts] = await signer.getNonce();
                this.forwarderContract[chainId][accounts] = new ethers.Contract(this.forwarderAddress[chainId], forwarderABI, signer);
            }
        }
        await Promise.all([this.updateGasPrice(), this.updateGasBalance()]);
        this.isGettingReady = false;
        console.log("INFO: Node is ready!");
    }

    async execute(forwardRequest, signature, orderType, chainId, pairId, gasLimit) {

        const keyIndex = this.keyIndex++%10;

        const contract = this.forwarderContract[chainId][keyIndex];

        const publicProvider = this.publicProviders[chainId];
        const provider = this.providers[chainId];
        const signer = await this.signers[chainId][keyIndex];

        let func;
        switch(orderType) {
            case "marketOpen":
                func = "executeWithPrice";
                break;
            case "marketClose":
                func = "executeWithPrice";
                break;
            case "createLimitOrder":
                func = "executeWithoutPrice";
                break;
            case "addToPosition":
                func = "executeWithPrice";
                break;
            case "addMargin":
                func = "executeWithPrice";
                break;
            case "removeMargin":
                func = "executeWithPrice";
                break;
            case "cancelLimitOrder":
                func = "executeWithoutPrice";
                break;
            case "updateTpSl":
                func = "executeWithPrice";
                break;
            case "openTrade":
                func = "executeWithPrice";
                break;
            case "initiateLimitOrder":
                func = "executeWithoutPrice";
                break;
        }

        const values = [forwardRequest, signature]

        if (func === "executeWithPrice") {
            if (pairId === undefined || pairId === null) {
                return {receipt: null, reason: "Pair ID not provided."};
            }
            const PriceData = this.latestPriceData[pairId];
            if (!PriceData) {
                console.log("ERROR: Price data not found!");
                return {receipt: null, reason: "Node failed to get price data."};
            }
            values.push([
                PriceData.provider,
                PriceData.is_closed,
                PriceData.asset,
                PriceData.price,
                PriceData.spread,
                PriceData.timestamp,
                PriceData.signature
            ]);
        }

        const transaction = {
            from: await signer.getAddress(),
            to: await contract.getAddress(),
            chainId: chainId,
            nonce: this.nonces[chainId][keyIndex],
            gasLimit: gasLimit,
            maxFeePerGas: this.gasData[chainId],
            maxPriorityFeePerGas: this.gasData[chainId],
            data: contract.interface.encodeFunctionData(func, values)
        };

        const signedTransaction = await signer.signTransaction(transaction);

        try {
            let transactionHash;
            try {
                transactionHash = await provider.send('eth_sendRawTransaction', [signedTransaction]);
            } catch {
                console.log("WARNING: Private RPC failed, trying public.");
                transactionHash = await publicProvider.send('eth_sendRawTransaction', [signedTransaction]);
            }


            this.nonces[chainId][keyIndex]++;

            const receipt = await provider.waitForTransaction(transactionHash);
            if (receipt.logs.length === 0 || (chainId === 137 && receipt.logs.length === 1)) {
                console.log("ERROR: Transaction " + transactionHash + " failed!");
                // Simulate the transaction to get the revert reason
                try {
                    const tx = await provider.getTransaction(transactionHash);
                    delete tx.gasPrice;
                    tx.blockTag = receipt.blockNumber;
                    await provider.call(tx); // Using `eth_call` to simulate the transaction
                } catch (error) {
                    console.log("Reason: ", error.reason);
                    return {receipt: receipt, reason: error.reason};
                }
            }
            console.log("INFO: Transaction " + transactionHash + " successful!");
            return {receipt: receipt};
        } catch(err) {
            console.log(err.reason ?? err.message);
            return {receipt: null, reason: "Node failed to send transaction."};
        }
    }

    // Verifies typed data signature for a forward request
    async verifySignature(request) {
        const domain = {
            name: "PermissionedForwarder",
            version: "1",
            chainId: request.chainId,
            verifyingContract: this.forwarderAddress[request.chainId]
        };
        const types = {
            ForwardRequest: [
                {name: 'from', type: 'address' },
                {name: 'to', type: 'address' },
                {name: 'salt', type: 'bytes32' },
                {name: 'deadline', type: 'uint256' },
                {name: 'data', type: 'bytes' },
            ]
        };
        const value = {
            from: request.from,
            to: request.to,
            salt: request.salt,
            deadline: request.deadline,
            data: request.data
        }
        const signature = request.signature;
        let recoveredAddress;
        try {
            recoveredAddress = ethers.verifyTypedData(domain, types, value, signature);
        } catch {
            return false;
        }
        return recoveredAddress === request.from;
    }

    chainIdToSymbol(chainId) {
        switch(chainId) {
            case 137:
                return "MATIC";
            case 82:
                return "MTR";
            default:
                return "ETH";
        }
    }

    async validateState(request) {
        const chainId = request.chainId;
        const traderAddress = '0x' + request.data.slice(-40);
        const validatePromises = [
            this.validateUserGasBalance(traderAddress, chainId),
            this.validateProxy(request.from, traderAddress, chainId),
            this.validateHash(request, chainId)
        ];
        try {
            const values = await Promise.all(validatePromises);
            if (values[0].valid && values[1].valid && values[2].valid) {
                return {valid: true, gasLimit: values[0].gasLimit};
            } else {
                if (!values[0].valid) {
                    return {valid: false, reason: "At least "
                            + String(Number(Number(values[0].gasNeeded).toPrecision(4))) + " "
                            + this.chainIdToSymbol(chainId) + " is needed in proxy wallet for gas."
                    };
                }
                if (!values[1].valid) {
                    return {valid: false, reason: "Proxy not approved."};
                }
                if (!values[2].valid) {
                    return {valid: false, reason: "Hash already used."}
                }
            }
        } catch (err) {
            console.log("ERROR: Failed to validate state.");
            console.log(err);
        }
        console.log("ERROR: Failed to validate state but returned valid.");
        return {valid: true};
    }

    async validateUserGasBalance(trader, chainId) {
        try {
            const forwarderContract = this.forwarderContract[chainId][0];

            // Check if the forwarder.userGas(trader) is enough
            const userGas = await forwarderContract.userGas(trader);
            const {gasNeeded, gasLimit} = await this.getGasRequirement(chainId);
            if (getBigInt(userGas) < gasNeeded) {
                return {valid: false, gasNeeded: formatEther(gasNeeded)};
            }
            return {valid: true, gasLimit: gasLimit};
        } catch (err) {
            console.log(err);
            return {valid: true, gasLimit: this.gasLimits[chainId]};
        }
    }

    async getGasRequirement(chainId) {
        if (chainId === 42161) {
            const gasLimit = getBigInt(this.gasLimits[42161]) + (getBigInt(200000) * getBigInt(this.gasData[1]) / getBigInt(1_000_000_000));
            return {gasNeeded: getBigInt(gasLimit) * getBigInt(this.gasData[42161]), gasLimit};
        } else {
            return {gasNeeded: getBigInt(this.gasLimits[chainId]) * getBigInt(this.gasData[chainId]), gasLimit: this.gasLimits[chainId]};
        }
    }

    async validateProxy(from, trader, chainId) {
        try {
            from = from.toLowerCase();
            if (from !== trader) {
                const provider = this.providers[chainId];
                const tradingAddress = this.tradingAddress[chainId];
                const tradingContract = new ethers.Contract(tradingAddress, tradingABI, provider);

                // check that trading.proxyApprovals(trader) == request.from
                const proxyApproval = (await tradingContract.proxyApprovals(trader)).toLowerCase();
                if (proxyApproval !== from) {
                    return {valid: false};
                }
            }
            return {valid: true};
        } catch (err) {
            console.log(err);
            return {valid: true};
        }
    }

    async validateHash(req, chainId) {
        try {
            const from = req.from;
            const to = req.to;
            const salt = req.salt;
            const deadline = req.deadline;
            const data = req.data;

            const hash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
                ["tuple(address from, address to, bytes32 salt, uint256 deadline, bytes data)"],
                [[from, to, salt, deadline, data]]
            ));

            const forwarderContract = this.forwarderContract[chainId][0];
            const isHashUsed = await forwarderContract.usedHashes(hash);
            if (isHashUsed) {
                return {valid: false};
            }
            return {valid: true};
        } catch (err) {
            console.log(err);
            return {valid: true};
        }
    }
}

async function main() {
    const x = new App();
}

main().catch((error) => {
    console.error(error);
});
