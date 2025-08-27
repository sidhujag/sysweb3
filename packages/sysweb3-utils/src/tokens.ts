import {
  Contract,
  type ContractFunction,
  type Event,
} from '@ethersproject/contracts';
import { retryableFetch } from '@sidhujag/sysweb3-network';
import * as sys from 'syscoinjs-lib';

import { createContractUsingAbi } from '.';
import ABI1155 from './abi/erc1155.json';
import abi20 from './abi/erc20.json';
import ABI721 from './abi/erc721.json';

import type { JsonRpcProvider } from '@ethersproject/providers';

const COINGECKO_API = 'https://api.coingecko.com/api/v3';

type NftMetadataMixedInJsonSchema = {
  properties: {
    description: { description: string; type: 'string' };
    image: { description: string; type: 'string' };
    name: { description: string; type: 'string' };
  };
  title: string;
  type: 'object';
};

export const RARIBLE_MATCH_RE =
  /^https:\/\/rarible\.com\/token\/(0x[a-fA-F0-9]{40}):([0-9]+)/;

export const isAddress = (value: string): value is Address =>
  /^0x[a-fA-F0-9]{40}$/.test(value);

export const identity = <T = unknown>(arg: T): T => arg;

export const parseNftUrl = (url: string): [string, string] | null => {
  const raribleMatch = RARIBLE_MATCH_RE.exec(url);

  if (raribleMatch) {
    return [raribleMatch[1], raribleMatch[2]];
  }

  return null;
};

export const fetchImage = (src: string): Promise<HTMLImageElement> =>
  new Promise((resolve, reject) => {
    const image = new Image();
    image.src = src;
    image.crossOrigin = '';
    image.onload = () => resolve(image);
    image.onerror = (error) => reject(error);
  });

export const normalizeTokenUrl = (url: string): string =>
  String(url).replace('ipfs://', 'https://ipfs.io/ipfs/');

export const normalizeImageUrl = (url: string): string =>
  normalizeTokenUrl(url);

export const normalizeNftMetadata = (
  data: NftJsonMetadata
): NftJsonMetadata => ({
  ...data,
  image: normalizeImageUrl(data.image),
});

export const ABI = [
  // ERC-721
  'function tokenURI(uint256 _tokenId) external view returns (string)',
  'function ownerOf(uint256 _tokenId) external view returns (address)',
  // ERC-1155
  'function uri(uint256 _id) external view returns (string)',
];

export const ERC20ABI = [
  'function balanceOf(address owner) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function transfer(address to, uint amount) returns (bool)',
  'event Transfer(address indexed from, address indexed to, uint amount)',
];

type NftContract = InstanceType<typeof Contract> & {
  balanceOf: ContractFunction<number>;
  ownerOf: ContractFunction<string>;
  tokenURI: ContractFunction<string>;
  uri: ContractFunction<string>;
};

type TokenContract = InstanceType<typeof Contract> & {
  Transfer: Event;
  balanceOf: ContractFunction<number>;
  decimals: ContractFunction<number>;
  symbol: ContractFunction<string>;
  transfer: ContractFunction<any>;
};

export const url = async (
  contract: NftContract,
  tokenId: string
): Promise<string> => {
  const uri = await promiseAny([
    contract.tokenURI(tokenId),
    contract.uri(tokenId),
  ]).catch((error: Error) => {
    throw new Error(
      `An error occurred while trying to fetch the token URI from the NFT contract. ${error}`
    );
  });

  return normalizeTokenUrl(uri);
};

export const fetchBalanceOfERC721Contract = async (
  contractAddress: string,
  address: string,
  provider: JsonRpcProvider
): Promise<number | undefined> => {
  const contract = new Contract(
    contractAddress,
    ABI721,
    provider
  ) as NftContract;

  const fetchBalanceOfValue = await contract.balanceOf(address);

  return fetchBalanceOfValue;
};

export const fetchBalanceOfERC1155Contract = async (
  contractAddress: string,
  address: string,
  provider: JsonRpcProvider,
  tokenId: number
): Promise<number | undefined> => {
  const contract = new Contract(
    contractAddress,
    ABI1155,
    provider
  ) as NftContract;

  const fetchBalanceOfValue = await contract.balanceOf(address, tokenId);

  return fetchBalanceOfValue;
};

export const getERC1155StandardBalance = async (
  contractAddress: string,
  address: string,
  provider: JsonRpcProvider,
  tokenId: number
) => {
  try {
    return await fetchBalanceOfERC1155Contract(
      contractAddress,
      address,
      provider,
      tokenId
    );
  } catch (error) {
    throw new Error(
      `Verify current network or the contract address. Set the same network of token contract. ${error}`
    );
  }
};

export const getERC721StandardBalance = async (
  contractAddress: string,
  address: string,
  provider: JsonRpcProvider
) => {
  try {
    return await fetchBalanceOfERC721Contract(
      contractAddress,
      address,
      provider
    );
  } catch (error) {
    throw new Error(
      `Verify current network or the contract address. Set the same network of token contract. ${error}`
    );
  }
};

export const fetchStandardNftContractData = async (
  contractAddress: Address,
  provider: JsonRpcProvider
): Promise<NftMetadata> => {
  // First try to determine the contract type
  let contractType = 'UNKNOWN';
  let contract: NftContract;

  try {
    // Try ERC-721 first
    const erc721Contract = new Contract(
      contractAddress,
      ABI721,
      provider
    ) as NftContract;

    // Check if it supports ERC-721 interface
    const isERC721 = await erc721Contract.supportsInterface('0x80ac58cd');
    if (isERC721) {
      contractType = 'ERC-721';
      contract = erc721Contract;
    } else {
      // Try ERC-1155
      const erc1155Contract = new Contract(
        contractAddress,
        ABI1155,
        provider
      ) as NftContract;

      const isERC1155 = await erc1155Contract.supportsInterface('0xd9b67a26');
      if (isERC1155) {
        contractType = 'ERC-1155';
        contract = erc1155Contract;
      } else {
        throw new Error('Contract does not support ERC-721 or ERC-1155');
      }
    }
  } catch (error) {
    // If supportsInterface fails, try to detect by calling methods
    // This is a fallback for contracts that don't implement ERC-165
    contract = new Contract(
      contractAddress,
      [...ABI721, ...ABI1155], // Combined ABI
      provider
    ) as NftContract;
  }

  // Try to get name and symbol
  let name = '';
  let symbol = '';

  try {
    // Try to get name
    name = await contract.name();
  } catch (error) {
    // Name might not be implemented (optional in ERC-1155)
    console.warn(
      `NFT contract ${contractAddress} does not implement name()`,
      error
    );
  }

  try {
    // Try to get symbol
    symbol = await contract.symbol();
  } catch (error) {
    // Symbol might not be implemented (optional in ERC-1155)
    console.warn(
      `NFT contract ${contractAddress} does not implement symbol()`,
      error
    );
  }

  // If neither name nor symbol is available, use a default
  if (!name && !symbol) {
    symbol = 'NFT';
    name = `${contractType} Collection`;
  }

  return {
    name: name || symbol || `${contractType} Collection`,
    symbol: cleanTokenSymbol(symbol || 'NFT'),
  };
};

/**
 * Clean token symbol by removing spam content
 * @param symbol - Raw token symbol that may contain spam
 * @returns Cleaned symbol with spam content removed
 */
export const cleanTokenSymbol = (symbol: string): string => {
  if (!symbol) return symbol;

  // Find first occurrence of common spam separators (: is most common)
  const separatorMatch = symbol.match(/[:\s|/\\()[\]{}<>=+&%#@!?;~`"'-]/);
  if (separatorMatch) {
    const cleanSymbol = symbol.substring(0, separatorMatch.index).trim();
    // Return cleaned symbol if it's valid, otherwise fallback to original
    return cleanSymbol.length > 0 ? cleanSymbol : symbol;
  }

  return symbol;
};

export const fetchStandardTokenContractData = async (
  contractAddress: Address,
  address: Address,
  provider: JsonRpcProvider
): Promise<{ balance: number; decimals: number; tokenSymbol: string }> => {
  const contract = new Contract(
    contractAddress,
    ERC20ABI,
    provider
  ) as TokenContract;

  const [balance, decimals, symbol] = await Promise.all([
    contract.balanceOf(address),
    contract.decimals(),
    contract.symbol(),
  ]);

  return {
    balance,
    decimals,
    tokenSymbol: cleanTokenSymbol(symbol),
  };
};

export const fixIncorrectImageField = (
  data: Record<string, unknown>
): Record<string, unknown> => {
  if (!data || typeof data !== 'object') {
    return data;
  }

  const _data = data as {
    image: string;
    imageUrl: string;
  };

  // makersplace.com is using `imageUrl` rather than `image`
  if (
    typeof _data.image === 'undefined' &&
    typeof _data.imageUrl === 'string'
  ) {
    return { ..._data, image: _data.imageUrl };
  }

  return data;
};

export const isNftMetadataMixedInJsonSchema = (
  data: unknown
): data is NftMetadataMixedInJsonSchema => {
  if (!data || typeof data !== 'object') {
    return false;
  }

  const _data = data as NftMetadataMixedInJsonSchema;

  return (
    _data.title === 'Asset Metadata' &&
    _data.type === 'object' &&
    typeof _data.properties.name.description === 'string' &&
    typeof _data.properties.image.description === 'string' &&
    typeof _data.properties.description.description === 'string' &&
    _data.properties.name.type === 'string' &&
    _data.properties.image.type === 'string' &&
    _data.properties.description.type === 'string'
  );
};

export const fixNftMetadataMixedInJsonSchema = (
  data: NftMetadataMixedInJsonSchema
): NftJsonMetadata => ({
  name: data.properties.name.description || '',
  description: data.properties.description.description || '',
  image: data.properties.image.description || '',
  rawData: { ...data },
});

export const isNftMetadata = (data: unknown): data is NftMetadata => {
  if (!data || typeof data !== 'object') {
    return false;
  }

  const _data = data as NftMetadata;

  return 'name' in _data || 'image' in _data;
};

export const addressesEqual = (
  address: Address,
  addressToCompare: Address
): boolean => address.toLowerCase() === addressToCompare.toLowerCase();

// Promise.any() implementation from https://github.com/m0ppers/promise-any
export const promiseAny = (promises: Promise<any>[]): Promise<any> =>
  reversePromise(
    Promise.all([...promises].map(reversePromise))
  ) as Promise<any>;

export const reversePromise = (promise: Promise<unknown>): Promise<unknown> =>
  new Promise((resolve, reject) => {
    Promise.resolve(promise).then(reject, resolve);
  });

export const IMAGE_EXT_RE = /\.(?:png|svg|jpg|jepg|gif|webp|jxl|avif)$/;
export const VIDEO_EXT_RE = /\.(?:mp4|mov|webm|ogv)$/;

export const getTokenStandardMetadata = async (
  contractAddress: string,
  address: string,
  provider: JsonRpcProvider
) => {
  try {
    return await fetchStandardTokenContractData(
      contractAddress,
      address,
      provider
    );
  } catch (error) {
    throw new Error(
      `Verify current network. Set the same network of token contract. ${error}`
    );
  }
};

export const getNftStandardMetadata = async (
  contractAddress: string,
  provider: JsonRpcProvider
) => {
  try {
    return await fetchStandardNftContractData(contractAddress, provider);
  } catch (error) {
    // Check if it's a network error
    if (error?.code === 'CALL_EXCEPTION' || error?.code === 'NETWORK_ERROR') {
      throw new Error(
        `Network error: Verify you are on the correct network for NFT contract ${contractAddress}. ${
          error?.message || error
        }`
      );
    }

    // Check if it's a contract not found error
    if (
      error?.message?.includes('Contract does not support ERC-721 or ERC-1155')
    ) {
      throw new Error(
        `Invalid NFT contract: ${contractAddress} does not appear to be an ERC-721 or ERC-1155 contract`
      );
    }

    // Generic error
    throw new Error(
      `Failed to fetch NFT metadata for ${contractAddress}: ${
        error?.message || error
      }`
    );
  }
};

/**
 * Converts a token to a fiat value
 *
 * Parameters should be all lower case and written by extense
 *
 * @param token Token to get fiat price from
 * @param fiat Fiat to convert token price to, should be a {@link [ISO 4217 code](https://docs.1010data.com/1010dataReferenceManual/DataTypesAndFormats/currencyUnitCodes.html)}
 * @example 'syscoin' for token | 'usd' for fiat
 */
export const getFiatValueByToken = async (
  token: string,
  fiat: string
): Promise<number> => {
  try {
    const response = await retryableFetch(
      `${COINGECKO_API}/simple/price?ids=${token}&vs_currencies=${fiat}`
    );
    const data = await response.json();
    return data[token][fiat];
  } catch (error) {
    throw new Error(`Unable to retrieve ${token} price as ${fiat} `);
  }
};

const isImageUrlAvailable = async (imageUrl: string) => {
  try {
    const response = await retryableFetch(imageUrl);

    return response.status === 200;
  } catch (error) {
    console.log('isImageUrlAvailable -->', { error });
    return false;
  }
};

export const getSearchTokenAtSysGithubRepo = async (tokenSymbol: string) => {
  const baseUrlToFetch = `https://raw.githubusercontent.com/syscoin/syscoin-rollux.github.io/master/data/${tokenSymbol}`;

  try {
    const imageUrl = `${baseUrlToFetch}/logo`;
    const dataUrl = `${baseUrlToFetch}/data.json`;

    const isPngImageAvailable = await isImageUrlAvailable(`${imageUrl}.png`);

    const formattedImgUrl = isPngImageAvailable
      ? `${imageUrl}.png`
      : `${imageUrl}.svg`;

    const tokenData = await retryableFetch(dataUrl);

    const formattedTokenData = await tokenData.json();

    if (formattedTokenData) {
      return {
        token: formattedTokenData,
        imageUrl: formattedImgUrl,
      };
    } else {
      return {
        token: null,
        imageUrl: '',
      };
    }
  } catch (error) {
    console.log('getSearchTokenAtSysGithubRepo error --> ', { error });
    return {
      token: null,
      imageUrl: '',
    };
  }
};
/**
 *
 * @param address Contract address of the token to validate
 */
export const validateToken = async (
  address: string,
  web3Provider: any
): Promise<IErc20Token | any> => {
  try {
    const contract = createContractUsingAbi(abi20, address, web3Provider);

    const [decimals, name, symbol]: IErc20Token[] = await Promise.all([
      contract.methods.decimals().call(),
      contract.methods.name().call(),
      contract.methods.symbol().call(),
    ]);

    const validToken = decimals && name && symbol;

    if (validToken) {
      return {
        name: String(name),
        symbol: String(symbol),
        decimals: Number(decimals),
      };
    }

    return console.error('Invalid token');
  } catch (error) {
    return console.error('Token not found, verify the Token Contract Address.');
  }
};

export const getAsset = async (
  explorerUrl: string,
  assetGuid: string
): Promise<
  | {
      assetGuid: string;
      contract: string;
      decimals: number;
      maxSupply: string;
      metaData?: string; // Syscoin 5 - general metadata field
      symbol: string;
      totalSupply: string;
    }
  | undefined
> => {
  try {
    // Validate inputs before API call
    if (!explorerUrl || !assetGuid) {
      throw new Error('Explorer URL and Asset GUID are required');
    }

    // Validate asset GUID format (should be numeric)
    if (!/^\d+$/.test(assetGuid)) {
      throw new Error('Invalid Asset GUID format');
    }

    const asset = await sys.utils.fetchBackendAsset(explorerUrl, assetGuid);

    if (!asset) {
      throw new Error(`Asset with guid ${assetGuid} not found`);
    }

    // Validate that this is not an invalid/unknown asset
    if (asset.symbol && asset.symbol.startsWith('UNKNOWN-')) {
      throw new Error(
        `Asset ${assetGuid} is invalid or unknown (${asset.symbol})`
      );
    }

    if (asset.metaData && asset.metaData === 'Unknown Asset Type') {
      throw new Error(`Asset ${assetGuid} is of unknown type`);
    }

    // Ensure symbol exists (required for Syscoin 5)
    if (!asset.symbol) {
      throw new Error(`Asset ${assetGuid} has no symbol`);
    }

    // Additional validation for proper asset
    if (!asset.symbol || asset.symbol.trim() === '') {
      throw new Error(`Asset ${assetGuid} has empty symbol`);
    }

    return asset;
  } catch (error) {
    console.error('getAsset error:', error);
    return;
  }
};

export const countDecimals = (x: number) => {
  if (Math.floor(x) === x) return 0;

  return x.toString().split('.')[1].length || 0;
};

/** types */

// the source is in snake case
export interface ICoingeckoToken {
  assetPlatformId: string;
  blockTimeInMinutes: number;
  categories: string[];
  coingeckoRank: number;
  coingeckoScore: number;
  communityData: object;
  communityScore: number;
  contractAddress?: string;
  countryOrigin: string;
  description: object;
  developerData: object;
  developerScore: number;
  genesisDate?: string;
  localization: object;
  icoData?: object;
  id: string;
  sentimentVotesDownPercentage: number;
  name: string;
  marketCapRank: number;
  liquidityScore: number;
  platforms: object;
  image: {
    thumb: string;
    small: string;
    large: string;
  };
  marketData: {
    circulatingSupply: number;
    currentPrice: { [fiat: string]: number };
    fdvToTvlRatio?: number;
    fullyDilutedValuation: object;
    totalValueLocked?: object;
    totalVolume: { [fiat: string]: number };
    mcapToTvlRatio?: number;
    marketCap: { [fiat: string]: number };
    totalSupply?: number;
    maxSupply?: number;
    priceChange24H: number;
  };
  sentimentVotesUpPercentage: number;
  publicInterestScore: number;
  hashingAlgorithm?: string;
  symbol: string;
  links: object;
  publicInterestStats: object;
  lastUpdated: string;
  tickers: object[];
}

export interface ICoingeckoSearchResultToken {
  id: string;
  large: string;
  marketCapRank: number;
  name: string;
  symbol: string;
  thumb: string;
}

export interface ICoingeckoSearchResults {
  categories: object[];
  coins: ICoingeckoSearchResultToken[];
  exchanges: object[];
  icos: object[];
  nfts: object[];
}

export type EthTokenDetails = {
  contract: string;
  decimals: number;
  description: string;
  id: string;
  name: string;
  symbol: string;
};

export type IEthereumAddress = {
  address: IEthereumBalance[];
};

export type IEthereumBalance = {
  balances: IEthereumCurrency[];
};

export type IEthereumCurrency = {
  currency: {
    symbol: string;
  };
  value: number;
};

export type IEthereumTokensResponse = {
  ethereum: IEthereumAddress;
};

export type IEthereumToken = {
  id: string;
  large: string;
  market_cap_rank: number;
  name: string;
  symbol: string;
  thumb: string;
};

export type TokenIcon = {
  largeImage: string;
  thumbImage: string;
};

export type NftResultDone = {
  error: undefined;
  loading: false;
  nft: NftMetadata;
  reload: () => Promise<boolean>;
  status: 'done';
};

export interface IEtherscanNFT {
  blockHash: string;
  blockNumber: string;
  confirmations: string;
  contractAddress: string;
  cumulativeGasUsed: string;
  from: string;
  gas: string;
  gasPrice: string;
  gasUsed: string;
  hash: string;
  input: string;
  nonce: string;
  transactionIndex: string;
  to: string;
  tokenDecimal: string;
  tokenID: string;
  tokenName: string;
  tokenSymbol: string;
  timeStamp: string;
}

export interface NftMetadata {
  name: string;
  symbol: string;
}

export type IErc20Token = {
  decimals: number;
  name: string;
  symbol: string;
};

export type ISyscoinToken = {
  balance: number;
  decimals: number;
  name: string;
  path: string;
  symbol: string;
  tokenId: string;
  totalReceived: string;
  totalSent: string;
  transfers: number;
  type: string;
};

export type IAddressMap = {
  changeAddress: string;
  outputs: [
    {
      address: string;
      value: number;
    }
  ];
};

export type Address = string;

export type NftResultLoading = {
  error: undefined;
  loading: true;
  nft: undefined;
  reload: () => Promise<boolean>;
  status: 'loading';
};

export type NftResultError = {
  error: Error;
  loading: false;
  nft: undefined;
  reload: () => Promise<boolean>;
  status: 'error';
};

export type IQueryFilterResult = Promise<Array<Event>>;

export type NftResult = NftResultLoading | NftResultError | NftResultDone;

export type NftJsonMetadata = {
  description: string;
  image: string;
  name: string;
  rawData: Record<string, unknown> | null;
};

export type ContractMethod = {
  address: string;
  humanReadableAbi: [string];
  methodHash: string;
  methodName: string;
};

/** end */
