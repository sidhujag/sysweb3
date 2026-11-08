export enum HardwareWalletType {
  LEDGER = 'ledger',
  TREZOR = 'trezor',
}

export enum ConnectionStatus {
  DISCONNECTED = 'disconnected',
  CONNECTING = 'connecting',
  CONNECTED = 'connected',
  ERROR = 'error',
}

export interface HardwareWalletStatus {
  type: HardwareWalletType;
  status: ConnectionStatus;
  connected: boolean;
  lastSeen?: number;
  error?: string;
  deviceInfo?: {
    model?: string;
    firmwareVersion?: string;
  };
}
