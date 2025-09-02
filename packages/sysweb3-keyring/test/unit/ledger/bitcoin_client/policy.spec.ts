import { ClientCommandInterpreter } from '../../../../src/ledger/bitcoin_client/lib/clientCommands';
import { WalletPolicy } from '../../../../src/ledger/bitcoin_client/lib/policy';

describe('WalletPolicy and ClientCommandInterpreter descriptor handling', () => {
  it('uses ASCII bytes for descriptorTemplate in interpreter preimages', () => {
    const descriptor = 'wpkh(@0/**)';
    const keys = ['[f23a9bcd/84h/0h/0h]xpub6CUGRU...'];

    const wp = new WalletPolicy('', descriptor, keys);
    const cci = new ClientCommandInterpreter();

    const seen: Buffer[] = [];
    const addKnownPreimage = (cci as any).addKnownPreimage.bind(cci);
    (cci as any).addKnownPreimage = (buf: Buffer) => {
      seen.push(Buffer.from(buf));
      return addKnownPreimage(buf);
    };

    cci.addKnownWalletPolicy(wp);

    const asciiDescriptor = Buffer.from(descriptor, 'ascii');
    const found = seen.some((b) => b.equals(asciiDescriptor));
    expect(found).toBe(true);
  });
});
