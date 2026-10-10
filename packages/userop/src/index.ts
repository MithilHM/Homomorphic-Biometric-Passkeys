/**
 * ERC-4337 UserOperation utilities for Monad
 */

import { UserOperation } from '@homobio/protocol-types';

export const MONAD_CHAIN_CONFIG = {
  chainId: 143,
  name: 'Monad Testnet',
  rpcUrl: 'https://testnet-rpc.monad.xyz',
  entryPoint: '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789',
  nativeCurrency: { name: 'MON', symbol: 'MON', decimals: 18 }
};

export class UserOperationBuilder {
  private userOp: Partial<UserOperation> = {
    nonce: '0x0',
    initCode: '0x',
    callData: '0x',
    callGasLimit: '0x186a0', // 100,000
    verificationGasLimit: '0x249f0', // 150,000
    preVerificationGas: '0xc350', // 50,000
    maxFeePerGas: '0x3b9aca00', // 1 gwei
    maxPriorityFeePerGas: '0x3b9aca00',
    paymasterAndData: '0x',
    signature: '0x'
  };

  public setSender(sender: string): this {
    this.userOp.sender = sender;
    return this;
  }

  public setNonce(nonce: string): this {
    this.userOp.nonce = nonce;
    return this;
  }

  public setCallData(callData: string): this {
    this.userOp.callData = callData;
    return this;
  }

  public setInitCode(initCode: string): this {
    this.userOp.initCode = initCode;
    return this;
  }

  public setGasLimits(limits: {
    callGasLimit?: string;
    verificationGasLimit?: string;
    preVerificationGas?: string;
  }): this {
    if (limits.callGasLimit) this.userOp.callGasLimit = limits.callGasLimit;
    if (limits.verificationGasLimit) this.userOp.verificationGasLimit = limits.verificationGasLimit;
    if (limits.preVerificationGas) this.userOp.preVerificationGas = limits.preVerificationGas;
    return this;
  }

  public setPaymaster(paymasterAndData: string): this {
    this.userOp.paymasterAndData = paymasterAndData;
    return this;
  }

  public setSignature(signature: string): this {
    this.userOp.signature = signature;
    return this;
  }

  public build(): UserOperation {
    if (!this.userOp.sender) {
      throw new Error('UserOperation sender address is required');
    }
    return this.userOp as UserOperation;
  }
}
