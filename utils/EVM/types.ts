import type * as ethers from 'ethers';
import {
  ChainProvider,
  ChainSignatureContracts,
  KeyDerivationPath,
  NearAuthentication,
  NearNetworkIds,
} from '../../types/near';

export type EVMTransaction = ethers.TransactionLike;

export type EVMChainConfigWithProviders = ChainProvider;

export interface EVMRequest {
  transaction: EVMTransaction;
  chainConfig: EVMChainConfigWithProviders;
  nearAuthentication: NearAuthentication;
  fastAuthRelayerUrl?: string;
  derivationPath: KeyDerivationPath;
}
export interface FetchEVMAddressRequest {
  signerId: string;
  path: KeyDerivationPath;
  nearNetworkId: NearNetworkIds;
  multichainContractId: ChainSignatureContracts;
}
