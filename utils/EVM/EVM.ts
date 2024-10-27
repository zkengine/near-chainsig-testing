import { ethers, keccak256, recoverAddress } from 'ethers';

import {
  ChainSignatureContracts,
  KeyDerivationPath,
  MPCSignature,
  NearAuthentication,
  RSVSignature,
} from '../../types/near';
import { toRSV } from '../utils';
import { type EVMTransaction } from './types';
import { fetchDerivedEVMAddress, fetchEVMFeeProperties } from './utils';

export class EVM {
  private readonly provider: ethers.JsonRpcProvider;
  private readonly contract: ChainSignatureContracts;
  private readonly signer: (txHash: Uint8Array) => Promise<MPCSignature>;

  constructor(config: {
    providerUrl: string;
    contract: ChainSignatureContracts;
    signer: (txHash: Uint8Array) => Promise<MPCSignature>;
  }) {
    this.provider = new ethers.JsonRpcProvider(config.providerUrl);
    this.contract = config.contract;
    this.signer = config.signer;
  }

  static prepareTransactionForSignature(
    transaction: ethers.TransactionLike
  ): Uint8Array {
    const serializedTransaction =
      ethers.Transaction.from(transaction).unsignedSerialized;
    const transactionHash = keccak256(serializedTransaction);

    return new Uint8Array(ethers.getBytes(transactionHash));
  }

  async sendSignedTransaction(
    transaction: ethers.TransactionLike,
    signature: ethers.SignatureLike
  ): Promise<ethers.TransactionResponse> {
    try {
      const serializedTransaction = ethers.Transaction.from({
        ...transaction,
        signature,
      }).serialized;
      return await this.provider.broadcastTransaction(serializedTransaction);
    } catch (error) {
      console.error('Transaction execution failed:', error);
      throw new Error('Failed to send signed transaction.');
    }
  }

  async attachGasAndNonce(
    transaction: Omit<EVMTransaction, 'from'> & { from: string }
  ): Promise<ethers.TransactionLike> {
    const hasUserProvidedGas =
      transaction.gasLimit &&
      transaction.maxFeePerGas &&
      transaction.maxPriorityFeePerGas;

    const { gasLimit, maxFeePerGas, maxPriorityFeePerGas } = hasUserProvidedGas
      ? transaction
      : await fetchEVMFeeProperties(
          this.provider._getConnection().url,
          transaction
        );

    const nonce = await this.provider.getTransactionCount(
      transaction.from,
      'latest'
    );

    const { from, ...rest } = transaction;

    return {
      gasLimit,
      maxFeePerGas,
      maxPriorityFeePerGas,
      chainId: this.provider._network.chainId,
      nonce,
      type: 2,
      ...rest,
    };
  }

  async getBalance(address: string): Promise<string> {
    try {
      const balance = await this.provider.getBalance(address);
      return ethers.formatEther(balance);
    } catch (error) {
      console.error(`Failed to fetch balance for address ${address}:`, error);
      throw new Error('Failed to fetch balance.');
    }
  }

  parseRSVSignature(rsvSignature: RSVSignature): ethers.Signature {
    const r = `0x${rsvSignature.r}`;
    const s = `0x${rsvSignature.s}`;
    const v = rsvSignature.v;

    return ethers.Signature.from({ r, s, v });
  }

  async handleTransaction(
    data: EVMTransaction,
    nearAuthentication: NearAuthentication,
    path: KeyDerivationPath
  ): Promise<ethers.TransactionResponse | undefined> {
    const derivedFrom = await fetchDerivedEVMAddress({
      signerId: nearAuthentication.accountId,
      path,
      nearNetworkId: nearAuthentication.networkId,
      multichainContractId: this.contract,
    });

    if (data.from && data.from.toLowerCase() !== derivedFrom.toLowerCase()) {
      throw new Error(
        'Provided "from" address does not match the derived address'
      );
    }

    const from = data.from || derivedFrom;

    const transaction = await this.attachGasAndNonce({
      ...data,
      from,
    });

    const txHash = EVM.prepareTransactionForSignature(transaction);

    const mpcSignature = await this.signer(txHash);

    const serializedTransaction =
      ethers.Transaction.from(transaction).unsignedSerialized;
    const transactionHash = keccak256(serializedTransaction);
    const payload = ethers.getBytes(transactionHash);
    const sig = ethers.Signature.from({
      r: '0x' + mpcSignature.big_r.affine_point.substring(2).toLowerCase(),
      s: '0x' + mpcSignature.s.scalar.toLowerCase(),
      v: mpcSignature.recovery_id,
    });
    const recoveryAddress = recoverAddress(payload, sig);
    console.log('recoveryAddress:::', recoveryAddress);

    const transactionResponse = await this.sendSignedTransaction(
      transaction,
      this.parseRSVSignature(toRSV(mpcSignature))
    );
    console.log('transactionResponse:::', transactionResponse);
    return transactionResponse;
  }
}
