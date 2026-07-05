declare module 'ethers/contract' {
  export { Contract } from 'ethers';
}

declare module 'ethers/address' {
  export { getAddress } from 'ethers';
}

declare module 'ethers/crypto' {
  export { Signature, keccak256 } from 'ethers';
}

declare module 'ethers/providers' {
  export { JsonRpcProvider } from 'ethers';
  export type { Networkish } from 'ethers';
}

declare module 'ethers/transaction' {
  export { Transaction } from 'ethers';
}

declare module 'ethers/utils' {
  export {
    dataSlice,
    formatEther,
    formatUnits,
    hexlify,
    isHexString,
    parseEther,
    parseUnits,
  } from 'ethers';
  export type { BytesLike } from 'ethers';
}
