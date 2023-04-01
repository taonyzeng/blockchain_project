var express = require('express');
var router = express.Router();
var fs = require('fs');
const db = require("../models");
const fetch = require('node-fetch');
var Web3 = require('web3');
const user = require("../controllers/user.controller.js");
const { exception } = require('console');

const config = JSON.parse(fs.readFileSync('./server-config.json', 'utf-8'));
const web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));
const contract_address = config.contracts.organizationManagerAddress;
const admin_address = config.admin_address; // org0
const admin_key = config.admin_key;
const contract = JSON.parse(fs.readFileSync('./build/contracts/OrganizationManager.json', 'utf-8'));

const formatDate = (current_datetime) => {
    let formatted_date = current_datetime.getFullYear() + "-" + (current_datetime.getMonth() + 1) + "-" + current_datetime.getDate() + " " + current_datetime.getHours() + ":" + current_datetime.getMinutes() + ":" + current_datetime.getSeconds();
    return formatted_date;
}

let isAuthenticated = function (req, res, next) {
    if (req.isAuthenticated()) {
        next();
    }
    else {
        // alert("Login first");
        req.flash('info', 'Login first.');
        res.redirect('/');
        // res.status(401).json({"message": 'User not authenticated.'});
    }
};

let getToken = async (req, res) => {
    let { provider_address, hashed } = req.query;
    let identity = hashed;
    if (!provider_address || provider_address.length === 0 || hashed === undefined) {
        return res.json({ msg: "Address of provider is not found." });
    }
    else {
        console.log(provider_address, hashed);

        let cur = "", provider_ip = "";
        let tokens = [];
        let errorMsg = "";
        for (let i = 0; i < provider_address.length; ++i) {
            cur = '0x' + provider_address[i].substr(2, provider_address[i].length - 2);
            provider_ip = config.org_mapping[cur][0];
            if (provider_ip === null) {
                return res.json({ msg: `IP of current provider ${cur} is not found.` })
            }
            else {
                let jwt = "";
                let signatureObject;
                let nonceObject;
                // prove org identity, it should be nonce from provider
                try {
                    await fetch(`http://${provider_ip}/users/auth/nonce?org=${admin_address}`)
                        .then(res => res.json())
                        .then(json => {
                            console.log(json);
                            nonceObject = json;
                        })
                        .catch((err) => {
                            console.log("GetNonce Error");
                            throw `Get Nonce Error with ${cur}, Error code:　${err.errno}`;
                        });
                } catch (e) {
                    console.log("contiue.", e);
                    errorMsg += e + "\n\n";
                    continue;
                }
                signatureObject = web3.eth.accounts.sign(nonceObject.nonce, admin_key);

                // get token
                try {
                    await fetch(`http://${provider_ip}/users/authenticate`, {
                        method: 'POST',
                        body: JSON.stringify({
                            identity: identity,
                            target_address: admin_address,
                            signature: signatureObject,
                            nonce: nonceObject
                        }),
                        headers: { 'Content-Type': 'application/json' }
                    })
                        .then(res => res.json())
                        .then(json => {
                            if (!json.success) return res.send({ status: false, message: json.message });
                            jwt = json.token
                        })
                        .catch((err) => {
                            console.log("Authenticate Error");
                            throw `Authenticate Error with ${cur}, Error code:　${err.errno}`
                        });
                } catch (e) {
                    console.log("contiue.", e);
                    errorMsg += e + "\n\n";
                    continue;
                }


                let token = {
                    identity: identity,
                    org: cur,
                    jwt: jwt
                }
                tokens.push(token);
            }
        }
        await db.tokens.bulkCreate(tokens, { updateOnDuplicate: ["jwt", "updatedAt"] });
        if (errorMsg.length !== 0)
            return res.json({ msg: errorMsg });
        res.json({ msg: "oK" });
    }
};

let getHashed = async (req, res, next) => {
    let opts = {
        filter: `(cn=${req.user.cn})`,
        scope: 'sub',
        attributes: ['hashed']
    };
    let searchResult = await user.userSearch(opts, 'ou=location2,dc=jenhao,dc=com');
    if (searchResult.length === 1) {
        let userObject = JSON.parse(searchResult[0]);
        console.log("MSG: user is not binding.")
        if (userObject.hashed === "")
            return res.redirect("/");
        req.user.hashed = userObject.hashed;
        next();
    }
    else {
        console.log("MSG: User not found.")
        return res.redirect("/");
    }
}

let getProtectedData = async (req, res, next) => {
    let tokens = await db.tokens.findAll({ where: { identity: req.user.hashed } });

    let contractInstance = new web3.eth.Contract(contract.abi, contract_address);

    // First: get user's ethereum address
    let user_address = "";
    await contractInstance.methods.getAddressByHashed(req.user.hashed).call({ from: admin_address })
        .then((result) => {
            user_address = result
        })
        .catch((e) => {
            return res.status(500).json({ msg: "failed to get address by hashed" });
        });

    // Second: get access manager contract of the user
    let accAddress = "";
    await contractInstance.methods.getAccessManagerAddress(user_address).call({ from: admin_address })
        .then((result) => {
            accAddress = result
        })
        .catch((err) => {
            return res.status(500).json({ msg: "failed to get acc manager" });
        });

    // Third: send request to resource provider with token.
    let data = [];
    let orgs = [];

    let date = [];
    let total = [];
    let resOrg = [];

    let provider_ip = "";
    let errorMsg = "";
    for (let i = 0; i < tokens.length; ++i) {
        provider_ip = config.org_mapping[tokens[i].org][0];
        if (provider_ip === null) {
            console.log(`IP of current provider ${tokens[i].org} is not found.`)
        }
        else {
            // get balance
            try {
                let result;
                await fetch(`http://${provider_ip}/users/protected?acc=${accAddress}`, {
                    headers: { 'x-access-token': tokens[i].jwt }
                })
                    .then(res => res.json())
                    .then(json => {
                        if (json.success) {
                            result = JSON.parse(json.data);
                            console.log(result);
                            orgs.push(tokens[i].org);
                            data.push(result.balance);

                            var date = new Date();
                            console.log(formatDate(date));

                            const accessBehavior = {
                                identity: req.user.hashed,
                                attribute: 'balance',
                                orgA: config.org_mapping['0x'+ admin_address.substr(2).toUpperCase()][1],
                                orgB: config.org_mapping[tokens[i].org][1],
                                timestamp: formatDate(date)
                            }
                            db.accessBehaviors.create(accessBehavior);

                        } else {
                            throw `Token expired. Please get token again with ${tokens[i].org}.${json.message}`;
                        }
                    })
                    .catch(err => {
                        console.log(`Get Data Error`, err);
                        throw `Get protected data Error with ${tokens[i].org}. ${err}`;
                    });
            } catch (e) {
                errorMsg += e + ".";
            }
            // end get balance

            // get bill
            try {
                await fetch(`http://${provider_ip}/users/protectedInvoice?acc=${accAddress}`, {
                    headers: { 'x-access-token': tokens[i].jwt }
                })
                    .then(res => res.json())
                    .then(json => {
                        console.log("GOT INVOICE!!!!");
                        if (json.success) {
                            result = json.data;
                            for (let j = 0; j < result.length; ++j) {
                                console.log(result[j]);
                                date.push(result[j].invoiceDate);
                                total.push(result[j].total);
                                resOrg.push(tokens[i].org);

                                var date = new Date();
                                console.log(formatDate(date));

                                const accessBehavior = {
                                    identity: req.user.hashed,
                                    attribute: 'bill',
                                    orgA: config.org_mapping['0x'+ admin_address.substr(2).toUpperCase()][1],
                                    orgB: config.org_mapping[tokens[i].org][1],
                                    timestamp: formatDate(date)
                                }
                                db.accessBehaviors.create(accessBehavior);
                            }
                        }
                    })
                    .catch(err => {
                        console.log(`Get Data Error`, err);
                        throw `Get protected invoice Error with ${tokens[i].org}. ${err}`;
                    });
            } catch (e) {
                errorMsg += e + '.';
            }

            // end get bill
        }
    }
    let invoices = await db.invoice.findAll({ where: { name: req.user.cn } });
    for (let i = 0; i < invoices.length; ++i) {
        date.push(invoices[i].invoiceDate);
        total.push(invoices[i].total);
        resOrg.push(admin_address);
    }

    console.log("current date");
    console.log(date);
    console.log("end log");
    req.errorMsg = errorMsg;
    req.data = data;
    req.orgs = orgs;
    req.date = date;
    req.total = total;
    req.resOrg = resOrg;
    next();
};

/* GET home page. */
router.get('/', isAuthenticated, getHashed, getProtectedData, async function (req, res) {
    let tokens = await db.tokens.findAll({ where: { identity: req.user.hashed } });
    let opts = {
        filter: `(cn=${req.user.cn})`,
        scope: 'one',
        attributes: ['mail', 'phone', 'balance'],
        attrsOnly: true
    };
    let data = await user.userSearch(opts, 'ou=location2,dc=jenhao,dc=com');
    let userObject = JSON.parse(data);
    console.log(userObject);
    res.render('dataSharing', {
        user: userObject,
        address: contract_address,
        org_address: admin_address,
        tokens: tokens,
        data: JSON.stringify(req.data),
        orgs: JSON.stringify(req.orgs),
        date: JSON.stringify(req.date),
        total: JSON.stringify(req.total),
        resOrg: JSON.stringify(req.resOrg),
        errorMsg: req.errorMsg,
        org_mapping: JSON.stringify(config.org_mapping)
    });
});

router.get('/getAccessToken', isAuthenticated, getToken);

router.get('/getOpenData', isAuthenticated, async function (req, res) {
    let tokens = await db.tokens.findAll({ where: { identity: req.user.hashed } });
    let data = [];
    let provider_ip = "";
    let result;
    for (let i = 0; i < tokens.length; ++i) {
        console.log(tokens[i].org);
        provider_ip = config.org_mapping[tokens[i].org][0];
        if (provider_ip == null) {
            console.log("provider ip is not found")
        }
        else {
            await fetch(`http://${provider_ip}/users/protected`, {
                headers: { 'x-access-token': tokens[i].jwt }
            })
                .then(res => res.json())
                .then(json => {
                    if (json.success) {
                        result = JSON.parse(json.data);
                        console.log(result);
                        data.push(result.phone);
                    }
                })
                .catch(err => console.log(err));
        }
    }

    res.render('dataSharing', { user: req.user, address: contract_address, org_address: admin_address, tokens: tokens, data: data });
});

module.exports = router;
