declare module 'ethers/abi' {
  export type { InterfaceAbi } from 'ethers';
}

declare module 'ethers/address' {
  export { isAddress } from 'ethers';
}

declare module 'ethers/contract' {
  export { Contract, EventLog } from 'ethers';
}

declare module 'ethers/providers' {
  export type { JsonRpcProvider } from 'ethers';
}
