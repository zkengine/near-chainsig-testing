import { Account, Connection, KeyPair } from 'near-api-js';
import { InMemoryKeyStore } from 'near-api-js/lib/key_stores';
import { type MPCSignature, type RSVSignature } from './types';

export const NEAR_MAX_GAS = BigInt('300000000000000');

export const toRSV = (signature: MPCSignature): RSVSignature => {
  return {
    r: signature.big_r.affine_point.substring(2),
    s: signature.s.scalar,
    v: signature.recovery_id,
  };
};

type SetConnectionArgs =
  | {
      networkId: string;
      accountId: string;
      keypair: KeyPair;
    }
  | {
      networkId: string;
      accountId?: never;
      keypair?: never;
    };

export const getNearAccount = async ({
  networkId,
  accountId = 'dontcare',
  keypair = KeyPair.fromRandom('ed25519'),
}: SetConnectionArgs): Promise<Account> => {
  const keyStore = new InMemoryKeyStore();
  await keyStore.setKey(networkId, accountId, keypair);

  const connection = Connection.fromConfig({
    networkId,
    provider: {
      type: 'JsonRpcProvider',
      args: {
        url: {
          testnet: 'https://rpc.testnet.near.org',
          mainnet: 'https://rpc.mainnet.near.org',
        }[networkId],
      },
    },
    signer: { type: 'InMemorySigner', keyStore },
  });

  return new Account(connection, accountId);
};
