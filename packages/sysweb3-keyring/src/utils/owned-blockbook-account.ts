import * as syscoinjs from 'syscoinjs-lib';

import type { SyscoinOwnedReadOptions } from '../types';

/** Read address paths with the host's endpoint policy and independent lifetime. */
export function fetchOwnedBlockbookAccount(
  backendUrl: string,
  xpub: string,
  transport: Pick<SyscoinOwnedReadOptions, 'fetch' | 'signal'>
): Promise<any> {
  if (
    typeof transport?.fetch !== 'function' ||
    typeof transport.signal?.aborted !== 'boolean'
  )
    throw new Error('Missing owned Blockbook account transport');
  return syscoinjs.utils.fetchBackendAccount(
    backendUrl,
    xpub,
    'tokens=used&details=tokens',
    true,
    undefined,
    transport
  );
}
