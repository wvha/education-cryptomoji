'use strict';

const { createHash } = require('crypto');
const signing = require('./signing');

/**
 * A simple validation function for transactions. Accepts a transaction
 * and returns true or false. It should reject transactions that:
 *   - have negative amounts
 *   - were improperly signed
 *   - have been modified since signing
 */
const isValidTransaction = transaction => {
  if (transaction.amount < 0) {
    return false;
  }
  const sum = transaction.source + transaction.recipient + transaction.amount;
  return signing.verify(transaction.source, sum, transaction.signature);
};

/**
 * Validation function for blocks. Accepts a block and returns true or false.
 * It should reject blocks if:
 *   - their hash or any other properties were altered
 *   - they contain any invalid transactions
 * 
 * My notes:
 *  this is similar to calculateHash from block
 *  if the current block hash isnt the same as the previous block hash
 *    then its been compromised
 *  also we check the block if every transaction is valid
 */
const isValidBlock = block => {
  const transactionString = block.transactions.map(t => t.signature).join('');
  const sumHash = block.previousHash + transactionString + block.nonce;

  if (block.hash !== createHash('sha512').update(sumHash).digest('hex')) {
    return false;
  }

  return block.transactions.every(isValidTransaction);
};

/**
 * One more validation function. Accepts a blockchain, and returns true
 * or false. It should reject any blockchain that:
 *   - is a missing genesis block
 *   - has any block besides genesis with a null hash
 *   - has any block besides genesis with a previousHash that does not match
 *     the previous hash
 *   - contains any invalid blocks
 *   - contains any invalid transactions
 * 
 * My notes:
 *  this function tests at the blockchain level as a whole.
 *    - contains genesis block
 *    - if any block's hash doesn't match its previous hash
 *    - checks each block if its a valid block
 *    - checks each transaction in block
 */
const isValidChain = blockchain => {
  const { blocks } = blockchain;

  if (blocks[0].previousHash !== null) {
    return false;
  }

  if (blocks.slice(1).some((b, i) => b.previousHash !== blocks[i].hash)) {
    return false;
  }

  if (blocks.some(b => !isValidBlock(b))) {
    return false;
  }

  return blocks
    .map(b => b.transactions)
    .reduce((flat, transactions) => flat.concat(transactions), [])
    .every(isValidTransaction);
};

/**
 * This last one is just for fun. Become a hacker and tamper with the passed in
 * blockchain, mutating it for your own nefarious purposes. This should
 * (in theory) make the blockchain fail later validation checks;
 */
const breakChain = blockchain => {
  blockchain.blocks[1].transactions[0].amount = 999999999;

};

module.exports = {
  isValidTransaction,
  isValidBlock,
  isValidChain,
  breakChain
};
