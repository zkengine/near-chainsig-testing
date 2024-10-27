import { KeyPair } from 'near-api-js';

/**
Available ChainSignature contracts:
  - Mainnet: v1.signer
  - Testnet: v1.signer-prod.testnet
  - Development (unstable): v1.signer-dev.testnet
*/
export type ChainSignatureContracts = string;

export interface ChainProvider {
  providerUrl: string;
  contract: ChainSignatureContracts;
}

export interface NearAuthentication {
  networkId: NearNetworkIds;
  keypair: KeyPair;
  accountId: string;
  deposit?: bigint;
}

interface SuccessResponse {
  transactionHash: string;
  success: true;
}

interface FailureResponse {
  success: false;
  errorMessage: string;
}

export type Response = SuccessResponse | FailureResponse;

export type NearNetworkIds = 'mainnet' | 'testnet';

export type SLIP044ChainId = 0 | 60 | 118;

export interface KeyDerivationPath {
  chain: SLIP044ChainId;
  domain?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  meta?: Record<string, any>;
}

export interface RSVSignature {
  r: string;
  s: string;
  v: number;
}

export interface MPCSignature {
  big_r: {
    affine_point: string;
  };
  s: {
    scalar: string;
  };
  recovery_id: number;
}
