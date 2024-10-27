import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { connect, KeyPair, keyStores } from 'near-api-js';
import { ChainSignatureContracts, NearAuthentication } from './types/near';
import { fetchDerivedEVMAddress } from './utils/EVM/utils';
import { ChainSignaturesContract } from './utils/signature';

dotenv.config();

async function main() {
  // const keyPair = KeyPair.fromRandom('ed25519');
  // const privateKey = keyPair.toString();
  // console.log('Private key:', privateKey);
  if (!process.env.PRIVATE_KEY) {
    throw new Error('PRIVATE_KEY is not set');
  }

  const keyPair = KeyPair.fromString(process.env.PRIVATE_KEY as any);
  const pk58 = keyPair.getPublicKey().data || [];
  const implicitAddress = Buffer.from(pk58).toString('hex');
  console.log('implicitAddress:::', implicitAddress);

  const myKeyStore = new keyStores.InMemoryKeyStore();
  await myKeyStore.setKey('testnet', implicitAddress, keyPair);

  const connectionConfig = {
    networkId: 'testnet',
    keyStore: myKeyStore,
    nodeUrl: 'https://rpc.testnet.near.org',
    walletUrl: 'https://wallet.testnet.near.org',
    helperUrl: 'https://helper.testnet.near.org',
    explorerUrl: 'https://explorer.testnet.near.org',
  };
  const near = await connect(connectionConfig);
  const account = await near.account(implicitAddress);
  try {
    await account.state();
  } catch (error: any) {
    if (error.type === 'AccountDoesNotExist') {
      console.log('Account does not exist. Creating...');
      const newAccount = await near.createAccount(
        implicitAddress,
        keyPair.getPublicKey()
      );
      console.log('Account created:', newAccount.accountId);
    } else {
      throw error;
    }
  }

  const transactionHash = ethers.randomBytes(32);
  const path = {
    chain: 60 as const,
    domain: "m/44'/60'/0'/0/0",
  };
  const nearAuthentication: NearAuthentication = {
    accountId: implicitAddress,
    deposit: BigInt('200000000000000000000000'),
    keypair: keyPair!,
    networkId: 'testnet',
  };

  const contract: ChainSignatureContracts = 'v1.signer-prod.testnet';

  try {
    const signature = await ChainSignaturesContract.sign({
      hashedTx: transactionHash,
      path,
      nearAuthentication,
      contract,
    });

    console.log('signature:::', signature);

    const derivedEVMAddress = await fetchDerivedEVMAddress({
      signerId: nearAuthentication.accountId,
      path,
      nearNetworkId: nearAuthentication.networkId,
      multichainContractId: contract,
    });
    console.log('Derived Ethereum address:::', derivedEVMAddress);

    const sig = ethers.Signature.from({
      r: '0x' + signature.big_r.affine_point.substring(2).toLowerCase(),
      s: '0x' + signature.s.scalar.toLowerCase(),
      v: signature.recovery_id,
    });
    const recoveredAddress = ethers.recoverAddress(transactionHash, sig);
    console.log('recovered address:::', recoveredAddress);

    console.log(
      'Is the recovered address equal to the derived ethereum address? \n',
      recoveredAddress.toLowerCase() === derivedEVMAddress.toLowerCase()
    );
  } catch (err) {
    console.log('error:::', err);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
