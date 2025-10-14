/* eslint-disable import/no-named-as-default */
import AppClient, { PartialSignature } from './lib/appClient';
import {
  DefaultDescriptorTemplate,
  DefaultWalletPolicy,
  WalletPolicy,
} from './lib/policy';
import { PsbtV2 } from './lib/psbtv2';

export { AppClient, PsbtV2, WalletPolicy, DefaultWalletPolicy };

export type { DefaultDescriptorTemplate, PartialSignature };

export default AppClient;
