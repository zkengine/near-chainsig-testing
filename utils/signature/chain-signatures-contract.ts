import { actionCreators } from '@near-js/transactions';
import { ethers } from 'ethers';
import { getNearAccount, NEAR_MAX_GAS } from './utils';

import { Account, Contract } from 'near-api-js';
import { type ExecutionOutcomeWithId } from 'near-api-js/lib/providers';
import {
  type ChainSignatureContracts,
  type KeyDerivationPath,
  type NearAuthentication,
  type NearNetworkIds,
} from '../../types/near';
import { parseSignedDelegateForRelayer } from '../relayer';
import { getCanonicalizedDerivationPath } from '../utils';
import { type MPCSignature } from './types';

interface SignArgs {
  payload: number[];
  path: string;
  key_version: number;
}

type MultiChainContract = Contract & {
  public_key: () => Promise<string>;
  sign: (args: {
    args: { request: SignArgs };
    gas: bigint;
    amount: bigint;
  }) => Promise<MPCSignature>;
  experimental_signature_deposit: () => Promise<number>;
};

export const ChainSignaturesContract = {
  getContract: ({
    account,
    contract,
  }: {
    account: Account;
    contract: ChainSignatureContracts;
  }): MultiChainContract => {
    return new Contract(account, contract, {
      viewMethods: ['public_key', 'experimental_signature_deposit'],
      changeMethods: ['sign'],
      useLocalViewExecution: false,
    }) as unknown as MultiChainContract;
  },

  getPublicKey: async ({
    networkId,
    contract,
  }: {
    networkId: NearNetworkIds;
    contract: ChainSignatureContracts;
  }): Promise<string | undefined> => {
    const nearAccount = await getNearAccount({ networkId });
    const chainSignaturesContract = ChainSignaturesContract.getContract({
      account: nearAccount,
      contract,
    });
    return await chainSignaturesContract.public_key();
  },

  getCurrentFee: async ({
    networkId,
    contract,
  }: {
    networkId: NearNetworkIds;
    contract: ChainSignatureContracts;
  }): Promise<bigint | undefined> => {
    const nearAccount = await getNearAccount({ networkId });
    const chainSignaturesContract = ChainSignaturesContract.getContract({
      account: nearAccount,
      contract,
    });

    return BigInt(
      (
        await chainSignaturesContract.experimental_signature_deposit()
      ).toLocaleString('fullwide', { useGrouping: false })
    );
  },

  sign: async ({
    hashedTx,
    path,
    nearAuthentication,
    contract,
    relayerUrl,
  }: {
    hashedTx: Uint8Array;
    path: KeyDerivationPath;
    nearAuthentication: NearAuthentication;
    contract: ChainSignatureContracts;
    relayerUrl?: string;
  }): Promise<MPCSignature> => {
    const account = await getNearAccount({
      networkId: nearAuthentication.networkId,
      accountId: nearAuthentication.accountId,
      keypair: nearAuthentication.keypair,
    });

    const mpcPayload = {
      payload: Array.from(ethers.getBytes(hashedTx)),
      path: getCanonicalizedDerivationPath(path),
      key_version: 0,
    };

    const deposit =
      nearAuthentication.deposit ??
      (await ChainSignaturesContract.getCurrentFee({
        networkId: nearAuthentication.networkId,
        contract,
      })) ??
      BigInt(1);

    try {
      return relayerUrl
        ? await signWithRelayer({
            account,
            contract,
            signArgs: mpcPayload,
            deposit,
            relayerUrl,
          })
        : await signDirect({
            account,
            contract,
            signArgs: mpcPayload,
            deposit,
          });
    } catch (e) {
      console.error(e);
      throw new Error('Signature error, please retry');
    }
  },
};

const signDirect = async ({
  account,
  contract,
  signArgs,
  deposit,
}: {
  account: Account;
  contract: ChainSignatureContracts;
  signArgs: SignArgs;
  deposit: bigint;
}): Promise<MPCSignature> => {
  const chainSignaturesContract = ChainSignaturesContract.getContract({
    account,
    contract,
  });

  const signature = await chainSignaturesContract.sign({
    args: { request: signArgs },
    gas: NEAR_MAX_GAS,
    amount: deposit,
  });

  return signature;
};

const signWithRelayer = async ({
  account,
  contract,
  signArgs,
  deposit,
  relayerUrl,
}: {
  account: Account;
  contract: ChainSignatureContracts;
  signArgs: SignArgs;
  deposit: bigint;
  relayerUrl: string;
}): Promise<MPCSignature> => {
  const functionCall = actionCreators.functionCall(
    'sign',
    { request: signArgs },
    BigInt(NEAR_MAX_GAS.toString()),
    BigInt(deposit.toString())
  );

  const signedDelegate = await account.signedDelegate({
    receiverId: contract,
    actions: [functionCall],
    blockHeightTtl: 60,
  });

  // Remove the cached access key to prevent nonce reuse
  delete account.accessKeyByPublicKeyCache[
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    signedDelegate.delegateAction.publicKey.toString()
  ];

  // TODO: add support for creating the signed delegate using the mpc recovery service with an oidc_token

  const res = await fetch(`${relayerUrl}/send_meta_tx_async`, {
    method: 'POST',
    mode: 'cors',
    body: JSON.stringify(parseSignedDelegateForRelayer(signedDelegate)),
    headers: new Headers({ 'Content-Type': 'application/json' }),
  });

  const txHash = await res.text();
  const txStatus = await account.connection.provider.txStatus(
    txHash,
    account.accountId,
    'FINAL'
  );

  const signature: string = txStatus.receipts_outcome.reduce<string>(
    (acc: string, curr: ExecutionOutcomeWithId) => {
      if (acc) {
        return acc;
      }
      const { status } = curr.outcome;
      return (
        (typeof status === 'object' &&
          status.SuccessValue &&
          status.SuccessValue !== '' &&
          Buffer.from(status.SuccessValue, 'base64').toString('utf-8')) ||
        ''
      );
    },
    ''
  );
  if (signature) {
    const parsedJSONSignature = JSON.parse(signature) as {
      Ok: MPCSignature;
    };
    return parsedJSONSignature.Ok;
  }
  throw new Error('Signature error, please retry');
};
