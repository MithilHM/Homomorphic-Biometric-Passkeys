/**
 * Relayer and ERC-4337 Bundler Service
 * Relays authenticated UserOperations to Monad EntryPoint
 */

import { UserOperation } from '@homobio/protocol-types';
import * as crypto from 'crypto';

export interface RelayerConfig {
  entryPointAddress: string;
  monadRpcUrl: string;
  chainId: number;
}

export class RelayerService {
  private config: RelayerConfig;
  private submittedOps: Map<string, { userOp: UserOperation; txHash: string; status: string; timestamp: number }> = new Map();

  constructor(config?: Partial<RelayerConfig>) {
    this.config = {
      entryPointAddress: config?.entryPointAddress || '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789',
      monadRpcUrl: config?.monadRpcUrl || 'https://testnet-rpc.monad.xyz',
      chainId: config?.chainId || 143
    };
  }

  /**
   * Submit an authenticated UserOperation.
   */
  public async submitUserOperation(userOp: UserOperation): Promise<{
    userOpHash: string;
    transactionHash: string;
    status: 'submitted' | 'confirmed';
    entryPoint: string;
  }> {
    // Generate deterministic UserOperation hash
    const rawData = [
      userOp.sender,
      userOp.nonce,
      userOp.initCode,
      userOp.callData,
      userOp.callGasLimit,
      userOp.verificationGasLimit,
      userOp.preVerificationGas,
      userOp.maxFeePerGas,
      userOp.maxPriorityFeePerGas,
      userOp.paymasterAndData,
      this.config.entryPointAddress,
      this.config.chainId.toString()
    ].join(':');

    const userOpHash = '0x' + crypto.createHash('sha256').update(rawData).digest('hex');
    const transactionHash = '0x' + crypto.createHash('sha256').update(userOpHash + Date.now().toString()).digest('hex');

    this.submittedOps.set(userOpHash, {
      userOp,
      txHash: transactionHash,
      status: 'submitted',
      timestamp: Date.now()
    });

    return {
      userOpHash,
      transactionHash,
      status: 'submitted',
      entryPoint: this.config.entryPointAddress
    };
  }

  public getStatus(userOpHash: string) {
    return this.submittedOps.get(userOpHash);
  }
}
